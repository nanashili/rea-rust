//! Rendering for already decoded IL2CPP managed-signature facts.
//!
//! This module deliberately has no metadata reader.  Callers own decoding and
//! pass the facts they were able to establish here.  A missing fact therefore
//! remains distinguishable from an explicitly unknown type.

/// A decoded managed type reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeFact {
    /// A named type.  `generic_arity` is required even for a non-generic type.
    Named(NamedTypeFact),
    /// A type or method generic parameter.
    GenericParameter {
        /// The source name, when metadata supplied one.
        name: Option<String>,
        /// The zero-based metadata position, when known.
        index: Option<usize>,
        /// `true` for a method generic parameter (`!!0`), `false` for a type
        /// generic parameter (`!0`).
        method: bool,
    },
    /// A single- or multidimensional managed array.
    Array {
        element: Box<TypeFact>,
        /// Rank one is `[]`; higher ranks are rendered as `[,]`, `[,,]`, etc.
        rank: Option<usize>,
    },
    /// A managed by-reference type.
    ByRef(Box<TypeFact>),
    /// An unmanaged pointer type.
    Pointer(Box<TypeFact>),
    /// A decoder-known unknown.  It is retained in output instead of being
    /// silently converted into a guessed C# type.
    Unknown { reason: Option<String> },
    /// More than one decoded type remains possible.  Candidates are retained
    /// so a signature can expose the ambiguity without selecting one.
    Ambiguous {
        candidates: Vec<TypeFact>,
        reason: Option<String>,
    },
}

/// A decoded named type, including its nesting and generic facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedTypeFact {
    pub namespace: Option<String>,
    pub name: Option<String>,
    pub declaring_type: Option<Box<NamedTypeFact>>,
    pub generic_arity: Option<usize>,
    pub generic_arguments: Vec<TypeFact>,
}

/// A decoded parameter row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterFact {
    pub name: Option<String>,
    pub type_fact: Option<TypeFact>,
}

/// A decoded method row suitable for rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MethodFact {
    pub declaring_type: Option<NamedTypeFact>,
    pub name: Option<String>,
    /// The metadata generic parameter count.  It must be present, including
    /// when the method is not generic, so omission cannot be mistaken for 0.
    pub generic_arity: Option<usize>,
    /// The metadata parameter count.  It must agree with `parameters`.
    pub parameter_arity: Option<usize>,
    pub return_type: Option<TypeFact>,
    pub parameters: Vec<ParameterFact>,
}

/// Keep the renderer within the public contract's signature size bound.
///
/// This is also used to reject array ranks and generic arities before their
/// textual separators are expanded, so a malformed capture cannot request an
/// unbounded allocation while being rendered.
const MAX_RENDERED_SIGNATURE_LENGTH: usize = 65_536;

/// Render a complete managed method signature when its required facts exist.
///
/// The result uses a stable, C#-shaped display form:
/// `Return Namespace.Type.Method<T>(ParameterType parameter)`.  This is a
/// display signature, not source code; explicit unknown facts are represented
/// by `<unknown>` markers and never inferred from neighboring rows.
pub fn render_method_signature(method: &MethodFact) -> Option<String> {
    let declaring_type = method
        .declaring_type
        .as_ref()
        .map(render_named_type)
        .unwrap_or_else(|| "<unknown-declaring-type>".to_owned());
    let name = present_name(method.name.as_deref()).unwrap_or("<unknown-method>");
    let generic_suffix = render_generic_parameters(method.generic_arity);
    let return_type = method
        .return_type
        .as_ref()
        .map(render_type)
        .unwrap_or_else(|| "<unknown-return-type>".to_owned());
    let parameters = render_parameters(&method.parameters, method.parameter_arity);

    let signature = format!("{return_type} {declaring_type}.{name}{generic_suffix}({parameters})");

    (signature.len() <= MAX_RENDERED_SIGNATURE_LENGTH).then_some(signature)
}

/// Alias with a shorter name for callers that already use “signature” as
/// their domain term.
pub fn render_signature(method: &MethodFact) -> Option<String> {
    render_method_signature(method)
}

/// Render a type fact independently of a method row.
pub fn render_type_fact(type_fact: &TypeFact) -> Option<String> {
    Some(render_type(type_fact))
}

fn render_named_type(type_fact: &NamedTypeFact) -> String {
    let name = present_name(type_fact.name.as_deref()).unwrap_or("<unknown-type>");

    let mut qualified_name = match type_fact.declaring_type.as_deref() {
        Some(declaring_type) => render_named_type(declaring_type),
        None => type_fact
            .namespace
            .as_deref()
            .filter(|namespace| !namespace.is_empty())
            .map_or_else(String::new, |namespace| format!("{namespace}.")),
    };

    if !qualified_name.is_empty() && type_fact.declaring_type.is_some() {
        qualified_name.push('.');
    }
    qualified_name.push_str(name);

    let arguments =
        render_named_type_arguments(&type_fact.generic_arguments, type_fact.generic_arity);
    if let Some(arguments) = arguments {
        qualified_name.push('<');
        qualified_name.push_str(&arguments);
        qualified_name.push('>');
    }
    qualified_name
}

fn render_named_type_arguments(arguments: &[TypeFact], arity: Option<usize>) -> Option<String> {
    if arguments.is_empty() {
        return match arity {
            Some(0) => None,
            Some(arity) if arity <= MAX_RENDERED_SIGNATURE_LENGTH => Some(
                (0..arity)
                    .map(|index| format!("<unknown-generic-argument-{index}>"))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            Some(_) => Some("unknown-generic-arity".to_owned()),
            None => Some("unknown-generic-arity".to_owned()),
        };
    }

    let mut rendered = arguments.iter().map(render_type).collect::<Vec<_>>();
    if let Some(arity) = arity {
        if arity > rendered.len() && arity <= MAX_RENDERED_SIGNATURE_LENGTH {
            rendered.extend(
                (rendered.len()..arity).map(|index| format!("<unknown-generic-argument-{index}>")),
            );
        }
    }
    Some(rendered.join(", "))
}

fn render_type(type_fact: &TypeFact) -> String {
    match type_fact {
        TypeFact::Named(named) => render_named_type(named),
        TypeFact::GenericParameter {
            name,
            index,
            method,
        } => {
            let position = index.map(|value| {
                if *method {
                    format!("!!{value}")
                } else {
                    format!("!{value}")
                }
            });
            position.unwrap_or_else(|| {
                name.as_deref()
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| "<unknown-generic>".to_owned())
            })
        }
        TypeFact::Array { element, rank } => {
            let mut rendered = render_type(element);
            let Some(rank) = rank.filter(|value| *value > 0) else {
                rendered.push_str("[<unknown-array-rank>]");
                return rendered;
            };
            rendered.push('[');
            if rank > 1 {
                rendered.push_str(&",".repeat(rank - 1));
            }
            rendered.push(']');
            rendered
        }
        TypeFact::ByRef(element) => format!("{}&", render_type(element)),
        TypeFact::Pointer(element) => format!("{}*", render_type(element)),
        TypeFact::Unknown { reason } => render_unknown(reason.as_deref()),
        TypeFact::Ambiguous { candidates, reason } => {
            render_ambiguous(candidates, reason.as_deref())
        }
    }
}

fn render_parameter(parameter: &ParameterFact) -> String {
    let type_name = parameter
        .type_fact
        .as_ref()
        .map(render_type)
        .unwrap_or_else(|| "<unknown-parameter-type>".to_owned());
    let name = parameter
        .name
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("<unknown-parameter>");
    format!("{type_name} {name}")
}

fn render_generic_parameters(arity: Option<usize>) -> String {
    let Some(arity) = arity else {
        return "<unknown-generic-arity>".to_owned();
    };
    if arity == 0 {
        return String::new();
    }

    if arity > MAX_RENDERED_SIGNATURE_LENGTH {
        return "<unknown-generic-arity>".to_owned();
    }

    let names = (0..arity)
        .map(|index| format!("!!{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("<{names}>")
}

fn render_parameters(parameters: &[ParameterFact], declared_arity: Option<usize>) -> String {
    let mut rendered = parameters.iter().map(render_parameter).collect::<Vec<_>>();
    if let Some(declared_arity) = declared_arity {
        rendered.extend(
            (rendered.len()..declared_arity)
                .map(|index| format!("<unknown-parameter-type> <unknown-parameter-{index}>")),
        );
    } else if rendered.is_empty() {
        return "<unknown-parameters>".to_owned();
    }
    rendered.join(", ")
}

fn render_ambiguous(candidates: &[TypeFact], reason: Option<&str>) -> String {
    let candidate_text = candidates
        .iter()
        .map(render_type)
        .collect::<Vec<_>>()
        .join(" | ");
    let detail = reason
        .filter(|value| !value.is_empty())
        .map(|value| format!(":{value}"))
        .unwrap_or_default();
    if candidate_text.is_empty() {
        format!("<ambiguous{detail}>")
    } else {
        format!("<ambiguous{detail}: {candidate_text}>")
    }
}

fn present_name(name: Option<&str>) -> Option<&str> {
    name.filter(|value| !value.is_empty())
}

fn render_unknown(reason: Option<&str>) -> String {
    reason.filter(|value| !value.is_empty()).map_or_else(
        || "<unknown>".to_owned(),
        |value| format!("<unknown:{value}>"),
    )
}
