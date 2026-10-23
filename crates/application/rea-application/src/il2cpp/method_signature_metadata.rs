//! Build managed method signatures from already decoded IL2CPP rows.
//!
//! The metadata byte decoder owns file interpretation.  This module only
//! joins normalized rows supplied by a caller, so absent type information is
//! reported as unresolved rather than guessed from an index or a name.

use crate::il2cpp::signature_renderer::{
    MethodFact, NamedTypeFact, ParameterFact, TypeFact, render_method_signature,
};
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "render_il2cpp_method_signatures";
const MAX_ROWS: usize = 200_000;

/// Project normalized metadata into rendered signatures and unresolved facts.
///
/// The input may contain direct arrays or a `metadata` wrapper.  Types must
/// provide `generic_arity` (or `generic_parameter_count`) when signatures are
/// expected; the existing metadata reader does not currently emit that fact.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .or_else(|| root.get("normalized_result").and_then(Value::as_object))
        .unwrap_or(root);
    let methods = rows(metadata, "methods")?;
    let types = rows(metadata, "types")?;
    let parameters = optional_rows(metadata, "parameters")?;
    let generic_containers = optional_rows(metadata, "generic_containers")?;
    let generic_instances =
        optional_rows_alias(metadata, &["generic_instances", "genericInstances"])?;
    let type_descriptors = optional_rows_alias(metadata, &["type_descriptors", "typeDescriptors"])?;
    let typespecs = optional_rows_alias(metadata, &["typespecs", "type_specs", "typeSpecs"])?;
    let generic_parameters =
        optional_rows_alias(metadata, &["generic_parameters", "genericParameters"])?;

    let mut items = Vec::with_capacity(methods.len());
    for (row, method) in methods.iter().enumerate() {
        let object = method
            .as_object()
            .ok_or_else(|| invalid_row("methods", row, "Expected an object"))?;
        let metadata_index = index(object, "metadata_index", "methods", row)?;
        let mut unresolved = Vec::new();
        let fact = build_method(
            object,
            types,
            parameters,
            generic_containers,
            generic_instances,
            type_descriptors,
            typespecs,
            generic_parameters,
            &mut unresolved,
        )?;
        let signature = fact.as_ref().and_then(render_method_signature);
        if signature.is_none() && unresolved.is_empty() {
            unresolved.push("required signature facts are incomplete".to_owned());
        }
        items.push(serde_json::json!({
            "metadata_index": metadata_index,
            "method": method,
            "signature": signature,
            "resolution": if unresolved.is_empty() { "resolved" } else { "unresolved" },
            "unresolved_reasons": unresolved,
        }));
    }

    let resolved = items
        .iter()
        .filter(|item| item["resolution"] == "resolved")
        .count();
    Ok(serde_json::json!({
        "operation": OPERATION,
        "items": items,
        "coverage": { "methods": methods.len(), "resolved": resolved },
        "limitations": ["Only normalized metadata rows are consumed; native addresses, generic instances, and missing type facts remain unresolved."]
    }))
}

fn build_method(
    method: &Map<String, Value>,
    types: &[Value],
    parameters: &[Value],
    generic_containers: &[Value],
    generic_instances: &[Value],
    type_descriptors: &[Value],
    typespecs: &[Value],
    generic_parameters: &[Value],
    unresolved: &mut Vec<String>,
) -> Result<Option<MethodFact>, Failure> {
    let owner = match method.get("declaring_type").and_then(Value::as_i64) {
        Some(value) if value >= 0 => {
            match row_for_metadata_index(types, value as u64, "types", unresolved) {
                Some(value) => named_type(value, types, type_descriptors, typespecs, unresolved, 0),
                None => {
                    unresolved.push("declaring type index is outside the type rows".into());
                    None
                }
            }
        }
        _ => {
            unresolved.push("declaring type is absent or unknown".into());
            None
        }
    };
    let return_type = type_fact(
        method.get("return_type"),
        types,
        type_descriptors,
        typespecs,
        unresolved,
        "return type",
    );
    let parameter_arity = method
        .get("parameter_count")
        .and_then(Value::as_u64)
        .map(|value| value as usize);
    let mut rendered_parameters = Vec::new();
    if let Some(count) = parameter_arity {
        if count > MAX_ROWS {
            return Err(invalid(
                "methods.parameter_count",
                "Parameter range is too large",
            ));
        }

        let start = method.get("parameter_start").and_then(Value::as_i64);
        if count > 0 && start.map_or(true, |value| value < 0) {
            unresolved.push("parameter range is unknown".into());
            append_unknown_parameters(&mut rendered_parameters, count, "parameter range");
        } else if let Some(start) = start.filter(|value| *value >= 0) {
            let start = start as usize;
            let end = start.checked_add(count).ok_or_else(|| {
                invalid("methods.parameter_count", "Parameter range is too large")
            })?;
            for index in start..end {
                let Some(parameter) =
                    row_for_metadata_index(parameters, index as u64, "parameters", unresolved)
                else {
                    unresolved.push("parameter row is not retained".into());
                    append_unknown_parameters(
                        &mut rendered_parameters,
                        end - index,
                        "parameter row",
                    );
                    break;
                };
                let object = parameter
                    .as_object()
                    .ok_or_else(|| invalid_row("parameters", index, "Expected an object"))?;
                let parameter_type = object
                    .get("type")
                    .filter(|value| !value.is_null())
                    .or_else(|| object.get("type_index"));
                rendered_parameters.push(ParameterFact {
                    name: object
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    type_fact: type_fact(
                        parameter_type,
                        types,
                        type_descriptors,
                        typespecs,
                        unresolved,
                        "parameter type",
                    ),
                });
            }
        } else if count == 0 {
            // A zero parameter count is complete even when the metadata reader
            // has no meaningful start offset to retain.
        } else {
            unresolved.push("parameter start/count is absent".into());
            append_unknown_parameters(&mut rendered_parameters, count, "parameter range");
        }
    } else {
        unresolved.push("parameter count is absent".into());
    }
    let generic_arity =
        resolve_generic_arity(method, generic_containers, generic_parameters, unresolved);
    let mut fact = MethodFact {
        declaring_type: owner,
        name: method
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        generic_arity,
        parameter_arity,
        return_type,
        parameters: rendered_parameters,
    };

    apply_generic_instance_substitution(
        method,
        generic_instances,
        types,
        type_descriptors,
        typespecs,
        &mut fact,
        unresolved,
    );

    Ok(Some(fact))
}

/// Resolve method generic arity from the most specific retained owner fact.
///
/// IL2CPP method rows normally point at a generic-container row.  That row
/// carries the parameter range; requiring the range to fit the retained
/// parameter rows prevents an apparently valid count from hiding truncated
/// metadata.  Direct method fields remain supported for callers that already
/// projected the container relationship.
fn resolve_generic_arity(
    method: &Map<String, Value>,
    generic_containers: &[Value],
    generic_parameters: &[Value],
    unresolved: &mut Vec<String>,
) -> Option<usize> {
    let (direct_value, direct_conflicted) =
        integer_alias_state(method, &["generic_arity", "generic_parameter_count"]);
    if direct_conflicted {
        unresolved.push("method generic arity aliases conflict".into());
        return None;
    }
    if let Some(value) = direct_value {
        return Some(value as usize);
    }

    let container_index = method
        .get("generic_container")
        .and_then(Value::as_i64)
        .filter(|index| *index >= 0)
        .map(|index| index as usize);
    if method.get("generic_container").and_then(Value::as_i64) == Some(-1) {
        unresolved.push("generic arity is absent because no generic container was retained".into());
        return None;
    }
    if let Some(index) = container_index {
        match row_for_metadata_index(
            generic_containers,
            index as u64,
            "generic_containers",
            unresolved,
        )
        .and_then(Value::as_object)
        {
            Some(container) => {
                let (count, count_conflicted) = integer_alias_state(
                    container,
                    &[
                        "generic_parameter_count",
                        "parameter_count",
                        "type_argc",
                        "type_count",
                    ],
                );
                if count_conflicted {
                    unresolved.push("generic container arity aliases conflict".into());
                    return None;
                }
                let count = count.map(|value| value as usize);
                let (start, start_conflicted) =
                    integer_alias_state(container, &["generic_parameter_start", "parameter_start"]);
                if start_conflicted {
                    unresolved.push("generic container parameter start aliases conflict".into());
                    return None;
                }
                let start = start.map(|value| value as usize);
                if let (Some(start), Some(count)) = (start, count) {
                    if retained_metadata_range(
                        generic_parameters,
                        start,
                        count,
                        "generic_parameters",
                        unresolved,
                    ) {
                        return Some(count);
                    }
                    unresolved
                        .push("generic container parameter range exceeds retained rows".into());
                    return None;
                }
                if let Some(count) = count {
                    return Some(count);
                }
                unresolved.push("generic container does not provide parameter count".into());
            }
            None => unresolved.push("generic container index is outside retained rows".into()),
        }
    }

    let start = method
        .get("generic_parameter_start")
        .and_then(Value::as_u64)
        .map(|value| value as usize);
    let (count, count_conflicted) = integer_alias_state(method, &["generic_parameter_count"]);
    let count = count.map(|value| value as usize);
    match (start, count) {
        (Some(start), Some(count))
            if !count_conflicted
                && retained_metadata_range(
                    generic_parameters,
                    start,
                    count,
                    "generic_parameters",
                    unresolved,
                ) =>
        {
            Some(count)
        }
        (Some(_), Some(_)) => {
            unresolved.push("method generic parameter range exceeds retained rows".into());
            None
        }
        _ => {
            unresolved.push("method generic arity is absent".into());
            None
        }
    }
}

#[derive(Default)]
struct GenericInstanceSubstitution {
    class_arguments: Vec<TypeFact>,
    method_arguments: Vec<TypeFact>,
}

fn apply_generic_instance_substitution(
    method: &Map<String, Value>,
    instances: &[Value],
    types: &[Value],
    descriptors: &[Value],
    typespecs: &[Value],
    fact: &mut MethodFact,
    unresolved: &mut Vec<String>,
) {
    let Some(substitution) =
        generic_instance_substitution(method, instances, types, descriptors, typespecs, unresolved)
    else {
        return;
    };

    if let Some(declaring_type) = fact.declaring_type.as_mut() {
        substitute_named_type(declaring_type, &substitution, unresolved);
    }
    if let Some(return_type) = fact.return_type.as_mut() {
        substitute_type(return_type, &substitution, unresolved);
    }
    for parameter in &mut fact.parameters {
        if let Some(type_fact) = parameter.type_fact.as_mut() {
            substitute_type(type_fact, &substitution, unresolved);
        }
    }
}

fn generic_instance_substitution(
    method: &Map<String, Value>,
    instances: &[Value],
    types: &[Value],
    descriptors: &[Value],
    typespecs: &[Value],
    unresolved: &mut Vec<String>,
) -> Option<GenericInstanceSubstitution> {
    let instance = method
        .get("generic_instance")
        .or_else(|| method.get("genericInstance"))
        .and_then(Value::as_object)
        .or_else(|| {
            let index = method
                .get("generic_instance_index")
                .or_else(|| method.get("genericInstanceIndex"))
                .and_then(Value::as_i64)
                .filter(|index| *index >= 0)? as u64;
            row_for_metadata_index(instances, index, "generic_instances", unresolved)
                .and_then(Value::as_object)
        });

    let instance = instance.or_else(|| {
        method
            .get("class_arguments")
            .or_else(|| method.get("class_argument_indices"))
            .or_else(|| method.get("method_arguments"))
            .or_else(|| method.get("method_argument_indices"))
            .or_else(|| method.get("generic_arguments"))
            .map(|_| method)
    })?;

    let class_arguments = instance_arguments(
        instance,
        &[
            "class_arguments",
            "class_argument_indices",
            "class_type_indices",
            "type_indices",
            "generic_arguments",
            "argument_indices",
            "arguments",
        ],
        types,
        descriptors,
        typespecs,
        unresolved,
        "class generic instance",
    );
    let method_arguments = instance_arguments(
        instance,
        &[
            "method_arguments",
            "method_argument_indices",
            "method_type_indices",
            "generic_arguments",
            "argument_indices",
            "arguments",
        ],
        types,
        descriptors,
        typespecs,
        unresolved,
        "method generic instance",
    );

    Some(GenericInstanceSubstitution {
        class_arguments,
        method_arguments,
    })
}

fn instance_arguments(
    instance: &Map<String, Value>,
    fields: &[&str],
    types: &[Value],
    descriptors: &[Value],
    typespecs: &[Value],
    unresolved: &mut Vec<String>,
    label: &str,
) -> Vec<TypeFact> {
    let Some(value) = fields.iter().find_map(|field| instance.get(*field)) else {
        return Vec::new();
    };
    let Some(arguments) = value.as_array() else {
        unresolved.push(format!("{label} arguments are not an array"));
        return Vec::new();
    };

    arguments
        .iter()
        .map(|argument| {
            let type_value = argument
                .as_object()
                .and_then(|object| object.get("type_reference").or_else(|| object.get("type")))
                .unwrap_or(argument);
            type_fact(
                Some(type_value),
                types,
                descriptors,
                typespecs,
                unresolved,
                label,
            )
            .unwrap_or_else(|| TypeFact::Unknown {
                reason: Some(label.to_owned()),
            })
        })
        .collect()
}

fn substitute_named_type(
    named: &mut NamedTypeFact,
    substitution: &GenericInstanceSubstitution,
    unresolved: &mut Vec<String>,
) {
    if let Some(declaring_type) = named.declaring_type.as_mut() {
        substitute_named_type(declaring_type, substitution, unresolved);
    }
    for argument in &mut named.generic_arguments {
        substitute_type(argument, substitution, unresolved);
    }
    if named.generic_arguments.is_empty() {
        if let Some(arity) = named.generic_arity {
            if arity > 0 {
                if substitution.class_arguments.len() >= arity {
                    named.generic_arguments = substitution.class_arguments[..arity].to_vec();
                } else {
                    unresolved.push(
                        "declaring type generic instance has fewer arguments than its arity".into(),
                    );
                }
            }
        }
    }
}

fn substitute_type(
    type_fact: &mut TypeFact,
    substitution: &GenericInstanceSubstitution,
    unresolved: &mut Vec<String>,
) {
    match type_fact {
        TypeFact::Named(named) => substitute_named_type(named, substitution, unresolved),
        TypeFact::GenericParameter {
            index: Some(index),
            method,
            ..
        } => {
            let arguments = if *method {
                &substitution.method_arguments
            } else {
                &substitution.class_arguments
            };
            let Some(argument) = arguments.get(*index) else {
                unresolved.push(format!(
                    "{} generic parameter {index} has no retained instance argument",
                    if *method { "method" } else { "type" }
                ));
                return;
            };
            let mut replacement = argument.clone();
            substitute_type(&mut replacement, substitution, unresolved);
            *type_fact = replacement;
        }
        TypeFact::GenericParameter {
            index: None,
            method,
            ..
        } => {
            unresolved.push(format!(
                "{} generic parameter has no retained index",
                if *method { "method" } else { "type" }
            ));
        }
        TypeFact::Array { element, .. } | TypeFact::ByRef(element) | TypeFact::Pointer(element) => {
            substitute_type(element, substitution, unresolved)
        }
        TypeFact::Ambiguous { candidates, .. } => {
            for candidate in candidates {
                substitute_type(candidate, substitution, unresolved);
            }
        }
        TypeFact::Unknown { .. } => {}
    }
}

fn named_type(
    value: &Value,
    types: &[Value],
    descriptors: &[Value],
    typespecs: &[Value],
    unresolved: &mut Vec<String>,
    depth: usize,
) -> Option<NamedTypeFact> {
    if depth > 64 {
        unresolved.push("nested type depth exceeds the supported bound".into());
        return None;
    }
    let object = value.as_object()?;
    let declaring_type = object
        .get("declaring_type")
        .and_then(Value::as_i64)
        .filter(|index| *index >= 0)
        .and_then(|index| row_for_metadata_index(types, index as u64, "types", unresolved))
        .and_then(|parent| named_type(parent, types, descriptors, typespecs, unresolved, depth + 1))
        .map(Box::new);
    let (generic_arity, generic_arity_conflicted) =
        integer_alias_state(object, &["generic_arity", "generic_parameter_count"]);
    let generic_arity = generic_arity
        .filter(|_| !generic_arity_conflicted)
        .map(|value| value as usize);
    if generic_arity_conflicted {
        unresolved.push("type generic arity aliases conflict".into());
    }
    let generic_arguments = object
        .get("generic_arguments")
        .and_then(Value::as_array)
        .map(|arguments| {
            arguments
                .iter()
                .map(|argument| {
                    type_fact(
                        Some(argument),
                        types,
                        descriptors,
                        typespecs,
                        unresolved,
                        "generic argument",
                    )
                    .unwrap_or(TypeFact::Unknown {
                        reason: Some("generic argument".into()),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if generic_arity.is_none() {
        unresolved.push("type generic arity is absent".into());
    }
    Some(NamedTypeFact {
        namespace: object
            .get("namespace")
            .and_then(Value::as_str)
            .map(str::to_owned),
        name: object
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        declaring_type,
        generic_arity,
        generic_arguments,
    })
}

fn append_unknown_parameters(parameters: &mut Vec<ParameterFact>, count: usize, reason: &str) {
    parameters.extend((0..count).map(|_| ParameterFact {
        name: None,
        type_fact: Some(TypeFact::Unknown {
            reason: Some(reason.to_owned()),
        }),
    }));
}

fn type_fact(
    value: Option<&Value>,
    types: &[Value],
    descriptors: &[Value],
    typespecs: &[Value],
    unresolved: &mut Vec<String>,
    label: &str,
) -> Option<TypeFact> {
    if let Some(object) = value.and_then(Value::as_object) {
        return descriptor_fact(object, types, descriptors, typespecs, unresolved, label);
    }
    let index = value.and_then(Value::as_i64);
    match index {
        Some(index) if index >= 0 => {
            row_for_metadata_index(types, index as u64, "types", unresolved)
                .and_then(|value| named_type(value, types, descriptors, typespecs, unresolved, 0))
                .map(TypeFact::Named)
                .or_else(|| {
                    unresolved.push(format!("{label} index is outside the type rows"));
                    Some(TypeFact::Unknown {
                        reason: Some(label.into()),
                    })
                })
        }
        Some(-1) | None => {
            unresolved.push(format!("{label} is absent or unknown"));
            Some(TypeFact::Unknown {
                reason: Some(label.into()),
            })
        }
        _ => {
            unresolved.push(format!("{label} index is invalid"));
            Some(TypeFact::Unknown {
                reason: Some(label.into()),
            })
        }
    }
}

fn descriptor_fact(
    object: &Map<String, Value>,
    types: &[Value],
    descriptors: &[Value],
    typespecs: &[Value],
    unresolved: &mut Vec<String>,
    label: &str,
) -> Option<TypeFact> {
    descriptor_fact_at_depth(object, types, descriptors, typespecs, unresolved, label, 0)
}

fn descriptor_fact_at_depth(
    object: &Map<String, Value>,
    types: &[Value],
    descriptors: &[Value],
    typespecs: &[Value],
    unresolved: &mut Vec<String>,
    label: &str,
    depth: usize,
) -> Option<TypeFact> {
    if depth > 64 {
        unresolved.push(format!(
            "{label} descriptor nesting exceeds the supported bound"
        ));
        return Some(TypeFact::Unknown {
            reason: Some(label.into()),
        });
    }

    if object.contains_key("type_reference") {
        return typespec_fact(
            object,
            types,
            descriptors,
            typespecs,
            unresolved,
            label,
            depth,
        );
    }

    if let Some(resolution) = object.get("resolution").and_then(Value::as_str) {
        if resolution != "resolved" {
            return Some(unknown_descriptor_fact(object, label, unresolved));
        }

        return projected_descriptor_fact(
            object,
            types,
            descriptors,
            typespecs,
            unresolved,
            label,
            depth,
        );
    }

    if let Some(index) = object.get("descriptor_index").and_then(Value::as_u64) {
        if let Some(descriptor) =
            row_for_metadata_index(descriptors, index, "type_descriptors", unresolved)
                .and_then(Value::as_object)
        {
            return descriptor_fact_at_depth(
                descriptor,
                types,
                descriptors,
                typespecs,
                unresolved,
                label,
                depth + 1,
            );
        }
        unresolved.push(format!(
            "{label} descriptor index is outside descriptor rows"
        ));
        return Some(TypeFact::Unknown {
            reason: Some(label.into()),
        });
    }
    if let Some(index) = object.get("typespec_index").and_then(Value::as_u64) {
        if let Some(spec) = row_for_metadata_index(typespecs, index, "typespecs", unresolved)
            .and_then(Value::as_object)
        {
            return descriptor_fact_at_depth(
                spec,
                types,
                descriptors,
                typespecs,
                unresolved,
                label,
                depth + 1,
            );
        }
        unresolved.push(format!("{label} typespec index is outside typespec rows"));
        return Some(TypeFact::Unknown {
            reason: Some(label.into()),
        });
    }
    let mut result = match object.get("kind").and_then(Value::as_str) {
        Some("generic_parameter") | Some("generic") => TypeFact::GenericParameter {
            name: object
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            index: object
                .get("index")
                .and_then(Value::as_u64)
                .map(|v| v as usize),
            method: object
                .get("method")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        },
        Some(kind) if primitive_type_name(kind).is_some() => primitive_type_fact(kind),
        _ => type_fact(
            object
                .get("type_index")
                .or_else(|| object.get("type"))
                .or_else(|| object.get("element_type")),
            types,
            descriptors,
            typespecs,
            unresolved,
            label,
        )?,
    };
    if object.contains_key("byref") && object.get("byref").and_then(Value::as_bool).is_none() {
        unresolved.push(format!("{label} byref modifier is invalid"));
    }
    if object.contains_key("pointer") && object.get("pointer").and_then(Value::as_bool).is_none() {
        unresolved.push(format!("{label} pointer modifier is invalid"));
    }
    if object
        .get("byref")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        result = TypeFact::ByRef(Box::new(result));
    }
    if object
        .get("pointer")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        result = TypeFact::Pointer(Box::new(result));
    }
    if let Some(rank) = object.get("array_rank").and_then(Value::as_u64) {
        if rank == 0 {
            unresolved.push(format!("{label} array rank must be positive"));
        } else {
            result = TypeFact::Array {
                element: Box::new(result),
                rank: Some(rank as usize),
            };
        }
    }
    Some(result)
}

fn typespec_fact(
    object: &Map<String, Value>,
    types: &[Value],
    descriptors: &[Value],
    typespecs: &[Value],
    unresolved: &mut Vec<String>,
    label: &str,
    depth: usize,
) -> Option<TypeFact> {
    let mut result = type_fact(
        object.get("type_reference"),
        types,
        descriptors,
        typespecs,
        unresolved,
        label,
    )?;

    let Some(arguments) = object.get("arguments").and_then(Value::as_array) else {
        return Some(result);
    };
    let facts = arguments
        .iter()
        .map(|argument| {
            let value = argument
                .as_object()
                .and_then(|value| value.get("type_reference").or_else(|| value.get("type")))
                .unwrap_or(argument);
            type_fact(
                Some(value),
                types,
                descriptors,
                typespecs,
                unresolved,
                "generic argument",
            )
            .unwrap_or(TypeFact::Unknown {
                reason: Some("generic argument".to_owned()),
            })
        })
        .collect::<Vec<_>>();

    if let TypeFact::Named(named) = &mut result {
        named.generic_arity = Some(facts.len());
        named.generic_arguments = facts;
    } else {
        unresolved.push(format!(
            "{label} generic arguments have no named type owner"
        ));
    }
    let _ = depth;
    Some(result)
}

/// Read the stable output of `project_il2cpp_type_descriptors` without
/// falling back to the positional shape of the source row.  The projector
/// deliberately places references and generic arguments in separate fields,
/// so those fields are the owning representation at this boundary.
fn projected_descriptor_fact(
    object: &Map<String, Value>,
    types: &[Value],
    descriptors: &[Value],
    typespecs: &[Value],
    unresolved: &mut Vec<String>,
    label: &str,
    depth: usize,
) -> Option<TypeFact> {
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if let Some(name) = primitive_type_name(kind) {
        return Some(TypeFact::Named(named_primitive(name)));
    }

    let references = object.get("references").and_then(Value::as_object);
    let details = object.get("details").and_then(Value::as_object);
    let mut result = match kind {
        "generic_parameter" | "generic" => TypeFact::GenericParameter {
            name: None,
            index: references
                .and_then(|value| value.get("generic_parameter_index"))
                .and_then(Value::as_u64)
                .map(|value| value as usize),
            method: references
                .and_then(|value| value.get("method"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
        },
        "generic_instantiation" => {
            let arguments = references
                .and_then(|value| value.get("arguments"))
                .or_else(|| details.and_then(|value| value.get("arguments")))
                .and_then(Value::as_array);
            let Some(_arguments) = arguments else {
                unresolved.push(format!(
                    "{label} generic instantiation arguments are absent"
                ));
                return Some(TypeFact::Unknown {
                    reason: Some(label.to_owned()),
                });
            };
            unresolved.push(format!(
                "{label} generic instantiation has arguments but no named type owner"
            ));
            TypeFact::Unknown {
                reason: Some(label.to_owned()),
            }
        }
        "class" | "value" => {
            let reference = references
                .and_then(|value| value.get("type_index"))
                .or_else(|| references.and_then(|value| value.get("class_index")));
            type_fact(reference, types, descriptors, typespecs, unresolved, label)?
        }
        "array" => {
            let element = references
                .and_then(|value| value.get("element_type_index"))
                .or_else(|| references.and_then(|value| value.get("type_index")))
                .and_then(|value| {
                    type_fact(
                        Some(value),
                        types,
                        descriptors,
                        typespecs,
                        unresolved,
                        label,
                    )
                })
                .unwrap_or(TypeFact::Unknown {
                    reason: Some(label.to_owned()),
                });
            TypeFact::Array {
                element: Box::new(element),
                rank: details
                    .and_then(|value| value.get("rank"))
                    .and_then(Value::as_u64)
                    .map(|value| value as usize),
            }
        }
        "byref" | "pointer" => {
            let element = references
                .and_then(|value| value.get("element_type_index"))
                .or_else(|| references.and_then(|value| value.get("type_index")))
                .and_then(|value| {
                    type_fact(
                        Some(value),
                        types,
                        descriptors,
                        typespecs,
                        unresolved,
                        label,
                    )
                })
                .unwrap_or(TypeFact::Unknown {
                    reason: Some(label.to_owned()),
                });
            if kind == "byref" {
                TypeFact::ByRef(Box::new(element))
            } else {
                TypeFact::Pointer(Box::new(element))
            }
        }
        _ => {
            unresolved.push(format!("{label} descriptor kind is unknown"));
            TypeFact::Unknown {
                reason: Some(label.to_owned()),
            }
        }
    };

    apply_descriptor_modifiers(object, &mut result, label, unresolved);
    let _ = depth;
    Some(result)
}

fn unknown_descriptor_fact(
    object: &Map<String, Value>,
    label: &str,
    unresolved: &mut Vec<String>,
) -> TypeFact {
    let reason = object
        .get("details")
        .and_then(Value::as_object)
        .and_then(|details| details.get("reason"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| label.to_owned());
    unresolved.push(format!("{label} descriptor is unresolved: {reason}"));
    TypeFact::Unknown {
        reason: Some(reason),
    }
}

fn primitive_type_fact(kind: &str) -> TypeFact {
    TypeFact::Named(named_primitive(
        primitive_type_name(kind).expect("checked primitive kind"),
    ))
}

fn named_primitive(name: &str) -> NamedTypeFact {
    NamedTypeFact {
        namespace: None,
        name: Some(name.to_owned()),
        declaring_type: None,
        generic_arity: Some(0),
        generic_arguments: Vec::new(),
    }
}

fn primitive_type_name(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "primitive_void" => "void",
        "primitive_boolean" => "bool",
        "primitive_char" => "char",
        "primitive_i1" => "sbyte",
        "primitive_u1" => "byte",
        "primitive_i2" => "short",
        "primitive_u2" => "ushort",
        "primitive_i4" => "int",
        "primitive_u4" => "uint",
        "primitive_i8" => "long",
        "primitive_u8" => "ulong",
        "primitive_r4" => "float",
        "primitive_r8" => "double",
        "primitive_string" => "string",
        "primitive_native_int" => "nint",
        "primitive_native_uint" => "nuint",
        "primitive_object" => "object",
        _ => return None,
    })
}

fn apply_descriptor_modifiers(
    object: &Map<String, Value>,
    result: &mut TypeFact,
    label: &str,
    unresolved: &mut Vec<String>,
) {
    if object.get("byref").and_then(Value::as_bool) == Some(true) {
        *result = TypeFact::ByRef(Box::new(result.clone()));
    }
    if object.get("pointer").and_then(Value::as_bool) == Some(true) {
        *result = TypeFact::Pointer(Box::new(result.clone()));
    }
    if let Some(rank) = object.get("array_rank").and_then(Value::as_u64) {
        if rank == 0 {
            unresolved.push(format!("{label} array rank must be positive"));
        } else {
            *result = TypeFact::Array {
                element: Box::new(result.clone()),
                rank: Some(rank as usize),
            };
        }
    }
}

/// Resolve a retained row by its source metadata identity.
///
/// Captured rows may arrive in a different order from the source file. When
/// identity fields are present, positional lookup would silently attach a
/// signature to the wrong type or parameter, so an absent or duplicate
/// identity remains unresolved. Positional fallback is retained for older
/// callers whose normalized rows predate explicit identities.
fn row_for_metadata_index<'a>(
    rows: &'a [Value],
    metadata_index: u64,
    collection: &str,
    unresolved: &mut Vec<String>,
) -> Option<&'a Value> {
    let has_identity = rows.iter().any(|row| {
        row.as_object().is_some_and(|object| {
            object.contains_key("metadata_index")
                || object.contains_key("index")
                || object.contains_key("source_index")
                || (collection == "type_descriptors"
                    && (object.contains_key("descriptor_index")
                        || object.contains_key("type_descriptor_index")))
                || (collection == "typespecs"
                    && (object.contains_key("typespec_index")
                        || object.contains_key("type_spec_index")))
        })
    });
    if !has_identity {
        return rows.get(metadata_index as usize);
    }

    let mut matches = rows.iter().filter(|row| {
        row.as_object().is_some_and(|object| {
            row_identity(object, collection, unresolved) == Some(metadata_index)
        })
    });
    let Some(first) = matches.next() else {
        return None;
    };
    if matches.next().is_some() {
        unresolved.push(format!(
            "{collection} metadata index {metadata_index} is ambiguous"
        ));
        return None;
    }
    Some(first)
}

fn row_identity(
    object: &Map<String, Value>,
    collection: &str,
    unresolved: &mut Vec<String>,
) -> Option<u64> {
    let metadata_index = object.get("metadata_index").and_then(Value::as_u64);
    let index = object.get("index").and_then(Value::as_u64);
    let source_index = object.get("source_index").and_then(Value::as_u64);
    let collection_index = match collection {
        "type_descriptors" => object
            .get("descriptor_index")
            .or_else(|| object.get("type_descriptor_index"))
            .and_then(Value::as_u64),
        "typespecs" => object
            .get("typespec_index")
            .or_else(|| object.get("type_spec_index"))
            .and_then(Value::as_u64),
        _ => None,
    };
    let identities = [metadata_index, index, source_index, collection_index];
    let first = identities.iter().flatten().copied().next();
    if identities
        .iter()
        .flatten()
        .copied()
        .any(|value| Some(value) != first)
    {
        if let (Some(metadata_index), Some(index)) = (metadata_index, index) {
            unresolved.push(format!(
                "{collection} row has conflicting metadata_index and index identities"
            ));
        }
        return None;
    }
    first
}

fn retained_metadata_range(
    rows: &[Value],
    start: usize,
    count: usize,
    collection: &str,
    unresolved: &mut Vec<String>,
) -> bool {
    let Some(end) = start.checked_add(count) else {
        return false;
    };
    (start..end)
        .all(|index| row_for_metadata_index(rows, index as u64, collection, unresolved).is_some())
}

fn rows<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a [Value], Failure> {
    let rows = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "Expected an array of normalized metadata rows"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(field, "Metadata row collection exceeds the bound"));
    }
    if let Some(index) = rows.iter().position(|row| !row.is_object()) {
        return Err(invalid_row(field, index, "Expected an object row"));
    }
    Ok(rows)
}

fn optional_rows<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a [Value], Failure> {
    object.get(field).map_or(Ok(&[]), |value| {
        let rows = value
            .as_array()
            .ok_or_else(|| invalid(field, "Expected an array"))?;
        if rows.len() > MAX_ROWS {
            return Err(invalid(field, "Metadata row collection exceeds the bound"));
        }
        if let Some(index) = rows.iter().position(|row| !row.is_object()) {
            return Err(invalid_row(field, index, "Expected an object row"));
        }
        Ok(rows)
    })
}

fn optional_rows_alias<'a>(
    object: &'a Map<String, Value>,
    fields: &[&str],
) -> Result<&'a [Value], Failure> {
    for field in fields {
        if object.contains_key(*field) {
            return optional_rows(object, field);
        }
    }
    Ok(&[])
}

fn index(
    object: &Map<String, Value>,
    field: &str,
    collection: &str,
    row: usize,
) -> Result<u64, Failure> {
    object.get(field).and_then(Value::as_u64).ok_or_else(|| {
        invalid_row(
            collection,
            row,
            "metadata_index must be a non-negative integer",
        )
    })
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP signature projection input is invalid.".into(),
        false,
        "Supply normalized IL2CPP method, type, and parameter rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}

fn integer_alias_state(object: &Map<String, Value>, aliases: &[&str]) -> (Option<u64>, bool) {
    let mut selected = None;
    let mut conflicted = false;
    for alias in aliases {
        let Some(value) = object.get(*alias) else {
            continue;
        };
        let Some(value) = value.as_u64() else {
            conflicted = true;
            continue;
        };
        if selected.is_some_and(|existing| existing != value) {
            conflicted = true;
        } else {
            selected = Some(value);
        }
    }
    (selected, conflicted)
}
