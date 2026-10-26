//! Small, shared facts used by semantic data-effect collectors.
//!
//! This is the Rust owner of the syntax-facing portion of
//! `javascriptSemanticDataEffectHelpers.ts`.  The module deliberately keeps
//! provenance and mutation decisions in their owning passes; these helpers
//! only resolve lexical bindings, projections, literals, and traversal order.

use crate::javascript::ast::{AstVisitor, Field, Node, traverse};

use super::ast_values::{ExactLiteral, read_exact_literal, static_property_key, unwrapped};
use super::mutation_initializers::effect_timing;
use super::projection::callable_id_for_node;
use super::provenance::BindingProvenance;
use super::require_origin::{require_exports_identity, require_origin};
use super::state::{ModuleOrigin, SemanticState};
use super::value_types::JsString;
use super::values::evaluate_semantic_provenance;

pub use super::state::ProjectionKey;

/// A binding reached through a destructuring projection.
#[derive(Clone, Debug)]
pub struct SemanticProjectedBinding<'a> {
    pub binding_id: String,
    pub identifier: Node<'a>,
    pub projection_path: Vec<ProjectionKey>,
    pub resolution: ProjectionResolution,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionResolution {
    Complete,
    Partial,
}

// Node is tied to the source lifetime. The public fact intentionally does not
// own an AST; callers should use `semantic_projected_binding_facts` when facts
// cross the analysis boundary. This private conversion is never exposed.
fn projected_binding<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    path: Vec<ProjectionKey>,
    partial: bool,
) -> Option<SemanticProjectedBinding<'a>> {
    let name = node.identifier_name()?;
    let index = state.resolve_binding(&node, name)?;
    Some(SemanticProjectedBinding {
        binding_id: state.binding(index).binding_id.clone(),
        identifier: node,
        projection_path: path,
        resolution: if partial {
            ProjectionResolution::Partial
        } else {
            ProjectionResolution::Complete
        },
    })
}

fn collect_pattern<'a>(
    state: &SemanticState<'a>,
    pattern: Node<'a>,
    path: Vec<ProjectionKey>,
    partial: bool,
    output: &mut Vec<SemanticProjectedBinding<'a>>,
) {
    match pattern.babel_type() {
        "Identifier" => {
            if let Some(binding) = projected_binding(state, pattern, path, partial) {
                output.push(binding);
            }
        }
        "AssignmentPattern" => {
            if let Some(left) = pattern.field(state.source, Field::Left) {
                collect_pattern(state, left, path, true, output);
            }
        }
        "RestElement" => {
            if let Some(argument) = pattern.field(state.source, Field::Argument) {
                let mut rest = path;
                rest.push(ProjectionKey::Dynamic);
                collect_pattern(state, argument, rest, true, output);
            }
        }
        "ObjectPattern" => {
            for property in pattern
                .field_list(state.source, Field::Properties)
                .into_iter()
                .flatten()
            {
                if property.babel_type() == "RestElement" {
                    collect_pattern(state, property, path.clone(), true, output);
                    continue;
                }
                let Some(value) = property.field(state.source, Field::Value) else {
                    continue;
                };
                let key = property
                    .field(state.source, Field::Key)
                    .and_then(|key| static_property_key(state.source, key, property.computed()))
                    .map(ProjectionKey::Name)
                    .unwrap_or(ProjectionKey::Dynamic);
                let mut next = path.clone();
                next.push(key.clone());
                collect_pattern(
                    state,
                    value,
                    next,
                    partial || matches!(key, ProjectionKey::Dynamic),
                    output,
                );
            }
        }
        "ArrayPattern" => {
            for (index, element) in pattern
                .field_list(state.source, Field::Elements)
                .into_iter()
                .enumerate()
            {
                if let Some(element) = element {
                    let mut next = path.clone();
                    next.push(ProjectionKey::Index(index));
                    collect_pattern(state, element, next, partial, output);
                }
            }
        }
        _ => {}
    }
}

/// Resolve the nearest variable or assignment owner of `node`.
pub fn assigned_semantic_result_bindings<'a>(
    node: Node<'a>,
    ancestors: &[Node<'a>],
    state: &SemanticState<'a>,
) -> Vec<SemanticProjectedBinding<'a>> {
    for owner in ancestors.iter().rev() {
        let (pattern, source) = match owner.babel_type() {
            "VariableDeclarator" => (
                owner.field(state.source, Field::Id),
                owner.field(state.source, Field::Init),
            ),
            "AssignmentExpression" => (
                owner.field(state.source, Field::Left),
                owner.field(state.source, Field::Right),
            ),
            _ => (None, None),
        };
        if let (Some(pattern), Some(source)) = (pattern, source)
            && assigned_source_is(node, source, state.source)
        {
            let mut output = Vec::new();
            collect_pattern(state, pattern, Vec::new(), false, &mut output);
            return output;
        }
        if callable_id_for_node(&state.context, owner).is_some() {
            return Vec::new();
        }
    }
    Vec::new()
}

fn assigned_source_is<'a>(node: Node<'a>, source: Node<'a>, text: &'a str) -> bool {
    let mut current = source;
    loop {
        if current.babel_type() == "AwaitExpression" {
            let Some(argument) = current.field(text, Field::Argument) else {
                return false;
            };
            current = argument;
            continue;
        }
        return unwrapped(text, current).key() == unwrapped(text, node).key();
    }
}

/// Facts suitable for serialization or differential comparison.
pub fn semantic_projected_binding_facts<'a>(
    bindings: &[SemanticProjectedBinding<'a>],
) -> Vec<(String, Vec<ProjectionKey>, ProjectionResolution)> {
    bindings
        .iter()
        .map(|binding| {
            (
                binding.binding_id.clone(),
                binding.projection_path.clone(),
                binding.resolution,
            )
        })
        .collect()
}

pub fn scalar_assigned_result_binding<'b>(
    bindings: &'b [SemanticProjectedBinding<'_>],
) -> Option<&'b str> {
    (bindings.len() == 1 && bindings[0].projection_path.is_empty())
        .then(|| bindings[0].binding_id.as_str())
}

/// Resolve the nearest direct variable or assignment owner before a callable.
pub fn outer_data_effect_binding<'a>(
    node: Node<'a>,
    context: &DataEffectTraversalContext<'a, '_>,
) -> Option<String> {
    let bindings = assigned_semantic_result_bindings(node, &context.ancestors, context.state);
    scalar_assigned_result_binding(&bindings).map(str::to_owned)
}

/// Traversal state shared by data-effect collectors.
pub struct DataEffectTraversalContext<'a, 's> {
    pub state: &'s SemanticState<'a>,
    pub callable_ids: &'s std::collections::HashSet<String>,
    pub callable_stack: Vec<String>,
    pub ancestors: Vec<Node<'a>>,
}

/// Traverse in Babel visitor order, maintaining the caller-owned ancestor list.
pub fn traverse_data_effects<'a, 's>(
    program: Node<'a>,
    context: &mut DataEffectTraversalContext<'a, 's>,
    mut visit: impl FnMut(Node<'a>, Option<Node<'a>>, &[Node<'a>], Option<&str>),
) {
    struct Visitor<'a, 's, F> {
        visit: F,
        context: crate::javascript::ast::AstContext<'a>,
        callable_ids: &'s std::collections::HashSet<String>,
        callable_stack: Vec<String>,
        admitted_callables: Vec<bool>,
        ancestors: Vec<Node<'a>>,
    }
    impl<'a, 's, F: FnMut(Node<'a>, Option<Node<'a>>, &[Node<'a>], Option<&str>)> AstVisitor<'a>
        for Visitor<'a, 's, F>
    {
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
            let admitted = callable_id_for_node(&self.context, node)
                .filter(|id| self.callable_ids.contains(id));
            self.admitted_callables.push(admitted.is_some());
            if let Some(id) = admitted {
                self.callable_stack.push(id);
            }
            let current = self.callable_stack.last().map(String::as_str);
            (self.visit)(*node, parent.copied(), &self.ancestors, current);
            self.ancestors.push(*node);
        }
        fn exit(&mut self, _node: &Node<'a>, _parent: Option<&Node<'a>>) {
            self.ancestors.pop();
            if self.admitted_callables.pop().unwrap_or(false) {
                self.callable_stack.pop();
            }
        }
    }
    let source = context.state.source;
    let ast_context = crate::javascript::ast::AstContext::new(context.state.context.program());
    let mut visitor = Visitor {
        visit: &mut visit,
        context: ast_context,
        callable_ids: context.callable_ids,
        callable_stack: Vec::new(),
        admitted_callables: Vec::new(),
        ancestors: Vec::new(),
    };
    let _ = traverse(program, source, &mut visitor, || {
        std::ops::ControlFlow::<()>::Continue(())
    });
    context.ancestors = visitor.ancestors;
}

pub fn data_effect_argument_binding_id<'a>(
    node: Option<Node<'a>>,
    state: &SemanticState<'a>,
) -> Option<String> {
    let node = node?;
    let name = node.identifier_name()?;
    state
        .resolve_binding(&node, name)
        .map(|index| state.binding(index).binding_id.clone())
}

pub fn data_effect_literal_string<'a>(node: Option<Node<'a>>, source: &'a str) -> Option<JsString> {
    match read_exact_literal(source, node?)? {
        ExactLiteral::String(value) => Some(value),
        _ => None,
    }
}

pub fn data_effect_member_callee<'a>(node: Node<'a>, source: &'a str) -> Option<Node<'a>> {
    let callee = node.field(source, Field::Callee)?;
    matches!(
        callee.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    )
    .then_some(callee)
}

pub fn is_semantic_process_object<'a>(
    node: Node<'a>,
    state: &SemanticState<'a>,
    family: &str,
    key: Option<&str>,
) -> bool {
    let mut selected = vec![super::property_paths::PropertyPathKey::String(
        JsString::from(family),
    )];
    if let Some(key) = key {
        selected.push(super::property_paths::PropertyPathKey::String(
            JsString::from(key),
        ));
    }
    if let Some(name) = node.identifier_name()
        && let Some(binding_index) = state.resolve_binding(&node, name)
    {
        let binding = state.binding(binding_index);
        return matches!(evaluate_semantic_provenance(binding, state), BindingProvenance::Module { ref origins } if origins.iter().any(|origin| {
            let normalized = require_exports_identity(&origin.specifier, &origin.imported_path);
            normalized.0 == "process" && normalized.1.is_empty()
        }));
    }
    if node.identifier_name() != Some("process") {
        return false;
    }
    state.is_unshadowed_global(&node, "process")
        && !state.ambient_write_effects.iter().any(|effect| {
            effect.path.len() >= selected.len()
                && effect
                    .path
                    .iter()
                    .zip(&selected)
                    .all(|(actual, wanted)| actual == wanted)
                && effect_timing(node, Some(effect.node), state, state.source)
                    != super::mutation_initializers::EffectTiming::After
        })
}

/// Built-in receiver methods accepted by resource/data-effect collectors.
///
/// This matcher intentionally returns `None` for unresolved or mutable
/// aliases. A false positive would turn an ordinary user function into a
/// resource effect, while an unknown result remains conservatively usable by
/// the caller's unknown-effect path.
pub fn builtin_data_effect_method<'a>(
    callee: Node<'a>,
    state: &SemanticState<'a>,
    specifiers: &[&str],
) -> Option<String> {
    let callee = unwrapped(state.source, callee);

    if callee.babel_type() == "SequenceExpression" {
        let final_expression = callee
            .field_list(state.source, Field::Expressions)
            .into_iter()
            .flatten()
            .last()?;
        return builtin_data_effect_method(final_expression, state, specifiers);
    }

    if callee.babel_type() == "Identifier" {
        let name = callee.identifier_name()?;
        let binding_index = state.resolve_binding(&callee, name)?;
        let binding = state.binding(binding_index);
        let BindingProvenance::Module { origins } = evaluate_semantic_provenance(binding, state)
        else {
            return None;
        };
        let origin = origins.first()?;
        let (specifier, path) = require_exports_identity(&origin.specifier, &origin.imported_path);
        if path.len() != 1
            || !specifiers.iter().any(|candidate| {
                let candidate = JsString::from(*candidate);
                candidate.strip_prefix("node:").unwrap_or(candidate) == specifier
            })
        {
            return None;
        }
        let method = path.first()?.clone();
        return builtin_method_name(&specifier, &method);
    }

    let property = callee
        .field(state.source, Field::Property)
        .and_then(|property| static_property_key(state.source, property, callee.computed()))?;
    if !matches!(
        callee.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    ) {
        return None;
    }
    if !method_may_match_specifiers(&property, specifiers) {
        return None;
    }
    let object = callee
        .field(state.source, Field::Object)
        .map(|node| unwrapped(state.source, node))?;
    if has_prior_member_effect(object, &property, callee, state) {
        return None;
    }
    let origin = module_origin_for_expression(object, state, 0)?;
    let (mut specifier, mut path) =
        require_exports_identity(&origin.specifier, &origin.imported_path);
    if origin.resolution_mode != Some(super::state::ResolutionMode::Require)
        && path.first().is_some_and(|value| value == "default")
    {
        path.remove(0);
    }
    if specifier == "fs" && path.first().is_some_and(|value| value == "promises") {
        specifier = JsString::from("fs/promises");
        path.remove(0);
    }
    if !specifiers.iter().any(|candidate| {
        let candidate = JsString::from(*candidate);
        candidate.strip_prefix("node:").unwrap_or(candidate) == specifier
    }) {
        return None;
    }
    if !path.is_empty() {
        return None;
    }
    builtin_method_name(&specifier, &property)
}

fn builtin_method_name(specifier: &JsString, property: &JsString) -> Option<String> {
    if !builtin_method_allowed(specifier, property) {
        return None;
    }

    property.try_to_string().ok()
}

fn builtin_method_allowed(specifier: &JsString, property: &JsString) -> bool {
    match specifier {
        value if value == "fs" => known_method(
            property,
            &[
                "open",
                "openSync",
                "createReadStream",
                "createWriteStream",
                "readFile",
                "readFileSync",
                "writeFile",
                "writeFileSync",
                "close",
                "closeSync",
                "existsSync",
            ],
        ),
        value if value == "fs/promises" => {
            known_method(property, &["open", "readFile", "writeFile"])
        }
        value if value == "net" || value == "tls" => {
            known_method(property, &["connect", "createConnection"])
        }
        value if value == "http" || value == "https" => known_method(property, &["request", "get"]),
        value if value == "child_process" => {
            known_method(property, &["spawn", "exec", "execFile", "fork"])
        }
        value if value == "process" => {
            known_method(property, &["cwd", "uptime", "hrtime", "nextTick"])
        }
        value if value == "timers" => known_method(
            property,
            &[
                "setTimeout",
                "setInterval",
                "setImmediate",
                "clearTimeout",
                "clearInterval",
                "clearImmediate",
            ],
        ),
        _ => false,
    }
}

/// Reject member properties that no supplied built-in family can accept.
///
/// This is an optimistic filter: the resolved module origin and imported path
/// still have to pass the authoritative checks in `builtin_data_effect_method`.
fn method_may_match_specifiers(property: &JsString, specifiers: &[&str]) -> bool {
    specifiers.iter().any(|candidate| {
        let normalized = candidate.strip_prefix("node:").unwrap_or(candidate);
        builtin_method_allowed(&JsString::from(normalized), property)
    })
}

fn known_method(property: &JsString, candidates: &[&str]) -> bool {
    candidates.iter().any(|candidate| property == *candidate)
}

fn has_prior_member_effect<'a>(
    object: Node<'a>,
    property: &JsString,
    capture: Node<'a>,
    state: &SemanticState<'a>,
) -> bool {
    let Some(name) = object.identifier_name() else {
        return false;
    };
    let Some(binding_index) = state.resolve_binding(&object, name) else {
        return false;
    };
    let binding = state.binding(binding_index);
    binding
        .member_writes
        .iter()
        .chain(binding.escaped_paths.iter())
        .any(|effect| {
            effect.node.is_some_and(|node| {
                !state.top_level_effect_follows_capture(capture, Some(node))
                    && effect.path.first().is_some_and(|key| {
                        matches!(key, super::property_paths::PropertyPathKey::String(value) if value == property)
                    })
            })
        })
}

fn module_origin_for_expression<'a>(
    node: Node<'a>,
    state: &SemanticState<'a>,
    depth: usize,
) -> Option<ModuleOrigin> {
    if depth > 32 {
        return None;
    }
    if let Some(required) = require_origin(state, Some(node)) {
        return Some(required.origin);
    }
    if node.babel_type() == "Identifier" {
        let name = node.identifier_name()?;
        let binding = state.resolve_binding(&node, name)?;
        let binding = state.binding(binding);
        if binding.direct_origins.len() == 1 {
            return binding.direct_origins.first().cloned();
        }
        if let BindingProvenance::Module { origins } = evaluate_semantic_provenance(binding, state)
        {
            if origins.len() == 1 {
                return origins.first().cloned();
            }
        }
        if binding.initializers.len() == 1 {
            return module_origin_for_expression(binding.initializers[0].node, state, depth + 1);
        }
    }
    if matches!(
        node.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    ) {
        let object = node
            .field(state.source, Field::Object)
            .map(|object| unwrapped(state.source, object))?;
        let key = node
            .field(state.source, Field::Property)
            .and_then(|property| static_property_key(state.source, property, node.computed()))?;
        let mut origin = module_origin_for_expression(object, state, depth + 1)?;
        origin.imported_path.push(key);
        return Some(origin);
    }
    None
}
