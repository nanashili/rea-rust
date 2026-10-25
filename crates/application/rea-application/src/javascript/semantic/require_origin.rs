//! CommonJS require origins and builtin identity projections.
//!
//! This module owns the syntax and lexical portion of
//! `javascriptSemanticRequireOrigin`.  Mutation timing for the CommonJS
//! wrapper is read from [`SemanticState`]; runtime module resolution remains
//! outside the semantic layer.

use std::ops::ControlFlow;

use crate::javascript::ast::{AstVisitor, Field, Node, traverse};

use super::ast_values::{ExactLiteral, read_exact_literal, static_property_key, unwrapped};
use super::module_interop::{ModuleInterop, create_module_interop, static_string};
use super::mutation_initializers::{EffectTiming, effect_timing};
use super::state::{
    DeclarationKind, DefinitionKind, ModuleOrigin, ModuleRequireWritesCache, ResolutionMode,
    SemanticState,
};
use super::value_types::JsString;

/// Facts returned for a proven literal `require` expression.
#[derive(Clone, Debug)]
pub struct RequireOrigin<'a> {
    pub origin: ModuleOrigin,
    pub call: Node<'a>,
}

/// Loader classification used by downstream resource and module analyses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequireLoaderFact {
    CommonJsLoader,
    FactoryLoader,
    CreateRequire,
    Local,
    Unknown,
}

/// Classify a bare `require`, `require.resolve`, or `require.main` call.
pub fn require_loader_at<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    factory_binding_ids: &[String],
) -> RequireLoaderFact {
    let Some(callee) = node.field(state.source, Field::Callee) else {
        return RequireLoaderFact::Local;
    };
    let callee = unwrapped(state.source, callee);
    let loader = if callee.identifier_name() == Some("require") {
        Some(callee)
    } else if matches!(
        callee.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    ) {
        let property = callee
            .field(state.source, Field::Property)
            .and_then(|property| static_property_key(state.source, property, callee.computed()));
        let object = callee
            .field(state.source, Field::Object)
            .map(|object| unwrapped(state.source, object));
        if property
            .as_ref()
            .is_some_and(|key| key == "resolve" || key == "main")
            && object.as_ref().and_then(Node::identifier_name) == Some("require")
        {
            object
        } else {
            None
        }
    } else {
        None
    };
    let Some(loader) = loader else {
        return RequireLoaderFact::Local;
    };

    let Some(binding_index) = state.resolve_binding(&loader, "require") else {
        return if state.resolution_blocked(&loader, "require")
            || state
                .ambient_binding_writes
                .get("require")
                .into_iter()
                .flatten()
                .any(|write| {
                    effect_timing(node, Some(*write), state, state.source) != EffectTiming::After
                })
        {
            RequireLoaderFact::Unknown
        } else {
            RequireLoaderFact::CommonJsLoader
        };
    };
    let binding = state.binding(binding_index);
    if factory_binding_ids
        .iter()
        .any(|id| id == &binding.binding_id)
    {
        return if binding.initializers.is_empty() {
            RequireLoaderFact::FactoryLoader
        } else {
            RequireLoaderFact::Unknown
        };
    }
    if state.is_unmodified_commonjs_wrapper_binding(&loader, "require") {
        return if binding
            .definitions
            .iter()
            .any(|definition| definition.kind == DefinitionKind::Function)
        {
            RequireLoaderFact::Local
        } else if binding_has_prior_write(state, binding_index, node) {
            RequireLoaderFact::Unknown
        } else {
            RequireLoaderFact::CommonJsLoader
        };
    }
    if is_wrapper_require_initializer(state, binding_index, node) {
        return RequireLoaderFact::CommonJsLoader;
    }
    if let Some(wrapper_binding) = state.commonjs_wrapper_binding_declaration(&loader, "require")
        && !binding_has_prior_write(state, wrapper_binding, node)
    {
        return RequireLoaderFact::CommonJsLoader;
    }
    if is_create_require_binding(state, binding_index) {
        return RequireLoaderFact::CreateRequire;
    }
    if matches!(
        binding.kind,
        DefinitionKind::Function | DefinitionKind::Class
    ) && state.stable_initializer(binding_index).is_some()
    {
        return RequireLoaderFact::Local;
    }
    if binding.declaration_kinds.len() == 1
        && binding.declaration_kinds[0] == DeclarationKind::Const
        && state
            .stable_initializer(binding_index)
            .is_some_and(|initializer| {
                matches!(
                    initializer.node.babel_type(),
                    "FunctionExpression" | "ArrowFunctionExpression"
                )
            })
    {
        return RequireLoaderFact::Local;
    }
    RequireLoaderFact::Unknown
}

fn binding_has_prior_write<'a>(
    state: &SemanticState<'a>,
    binding_index: usize,
    site: Node<'a>,
) -> bool {
    let writes_before_site = state
        .binding_writes
        .get(&state.binding(binding_index).binding_id)
        .into_iter()
        .flatten()
        .any(|write| effect_timing(site, Some(*write), state, state.source) != EffectTiming::After);
    if writes_before_site {
        return true;
    }

    state
        .binding(binding_index)
        .initializers
        .iter()
        .filter(|initializer| {
            !state
                .binding_writes
                .get(&state.binding(binding_index).binding_id)
                .into_iter()
                .flatten()
                .any(|write| node_within(state, initializer.node, *write))
        })
        .any(|initializer| {
            effect_timing(site, Some(initializer.node), state, state.source) != EffectTiming::After
        })
}

fn node_within<'a>(state: &SemanticState<'a>, node: Node<'a>, ancestor: Node<'a>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.key() == ancestor.key() {
            return true;
        }
        current = state.parent_of(&candidate);
    }
    false
}

fn is_wrapper_require_initializer<'a>(
    state: &SemanticState<'a>,
    binding_index: usize,
    node: Node<'a>,
) -> bool {
    let binding = state.binding(binding_index);
    let Some(scope_index) = state.scopes_by_id.get(&binding.scope_id).copied() else {
        return false;
    };
    if state.scopes[scope_index].kind.as_str() != "program"
        || binding.kind != DefinitionKind::Variable
        || binding.declaration_kinds != [DeclarationKind::Var]
        || binding.initializers.len() != 1
        || binding.initializers[0].node.key() != node.key()
    {
        return false;
    }
    let Some(assignment) = state.parent_of(&node) else {
        return false;
    };
    if assignment.babel_type() != "AssignmentExpression"
        || assignment.operator() != Some("=")
        || state.conditionally_skipped.contains(&node.key())
        || assignment
            .field(state.source, Field::Right)
            .map(|right| right.key())
            != Some(node.key())
    {
        return false;
    }
    let Some(statement) = state.parent_of(&assignment) else {
        return false;
    };
    if statement.babel_type() != "ExpressionStatement"
        || state.parent_of(&statement).map(|parent| parent.key()) != Some(state.program.key())
    {
        return false;
    }
    let Some(target) = assignment.field(state.source, Field::Left) else {
        return false;
    };
    let target = unwrapped(state.source, target);
    target.identifier_name() == Some("require")
        && state.resolve_binding(&target, "require") == Some(binding_index)
}

fn is_create_require_binding<'a>(state: &SemanticState<'a>, binding_index: usize) -> bool {
    let binding = state.binding(binding_index);
    if binding.initializers.len() != 1 {
        return false;
    }
    let Some(initializer) = state.stable_initializer(binding_index) else {
        return false;
    };
    if initializer.node.babel_type() != "CallExpression" {
        return false;
    }
    let Some(callee) = initializer.node.field(state.source, Field::Callee) else {
        return false;
    };
    let callee = unwrapped(state.source, callee);
    if let Some(root_name) = callee.identifier_name() {
        let Some(root_binding) = state.resolve_binding(&callee, root_name) else {
            return false;
        };
        let origins = &state.binding(root_binding).direct_origins;
        return origins.len() == 1
            && origins[0]
                .imported_path
                .last()
                .is_some_and(|path| path == "createRequire")
            && (origins[0].specifier == "module" || origins[0].specifier == "node:module");
    }

    let (root, members) = super::globals::member_path(state.source, callee);
    if !members
        .last()
        .is_some_and(|key| key.as_ref().is_some_and(|key| key == "createRequire"))
    {
        return false;
    }
    let Some(root_name) = root.identifier_name() else {
        return false;
    };
    let Some(root_binding) = state.resolve_binding(&root, root_name) else {
        return false;
    };
    let origins = &state.binding(root_binding).direct_origins;
    origins.len() == 1
        && origins[0].imported_path.is_empty()
        && (origins[0].specifier == "module" || origins[0].specifier == "node:module")
}

/// Return the source writes that may replace the CommonJS wrapper's
/// `module.require` slot. The cache is deliberately re-entrant: recursive
/// interop proof sees `Building` and must remain conservative, while only the
/// completed scan is retained for later consumers.
pub fn module_require_writes<'a>(state: &SemanticState<'a>) -> Vec<Node<'a>> {
    {
        let cache = state.module_require_writes.borrow();
        match &*cache {
            ModuleRequireWritesCache::Ready(writes) => return writes.clone(),
            ModuleRequireWritesCache::Building => return Vec::new(),
            ModuleRequireWritesCache::Empty => {}
        }
    }
    *state.module_require_writes.borrow_mut() = ModuleRequireWritesCache::Building;

    let mut collector = ModuleRequireWriteCollector {
        state,
        interop: create_module_interop(state),
        writes: Vec::new(),
    };
    let _ = traverse(state.program, state.source, &mut collector, || {
        ControlFlow::<()>::Continue(())
    });
    let writes = collector.writes;
    *state.module_require_writes.borrow_mut() = ModuleRequireWritesCache::Ready(writes.clone());
    writes
}

struct ModuleRequireWriteCollector<'s, 'a> {
    state: &'s SemanticState<'a>,
    interop: ModuleInterop<'a, 's>,
    writes: Vec<Node<'a>>,
}

impl<'a> AstVisitor<'a> for ModuleRequireWriteCollector<'_, 'a> {
    fn enter(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
        let target = if node.babel_type() == "AssignmentExpression" {
            node.field(self.state.source, Field::Left)
        } else if node.babel_type() == "UpdateExpression"
            || (node.babel_type() == "UnaryExpression" && node.operator() == Some("delete"))
        {
            node.field(self.state.source, Field::Argument)
        } else {
            None
        };
        if let Some(target) = target
            && is_module_require_target(self.state, target)
        {
            self.writes.push(*node);
        }

        if !matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression"
        ) {
            return;
        }
        let Some(invocation) = self.interop.intrinsic_invocation(*node) else {
            return;
        };
        if invocation.path.len() != 3 {
            return;
        }
        let owner = invocation.path[1].as_str();
        let Some(method) = invocation.path.last().map(String::as_str) else {
            return;
        };
        let Some(arguments) = invocation.arguments.as_deref() else {
            return;
        };
        let target = arguments.first().copied();
        if !target.is_some_and(|target| is_module_object(self.state, target)) {
            return;
        }
        let writes_require = match (owner, method) {
            ("Object" | "Reflect", "defineProperty") => {
                static_string(self.state, arguments.get(1).copied())
                    .is_none_or(|key| key == "require")
            }
            ("Object", "defineProperties") => {
                if let Some(descriptors) = arguments.get(1).copied() {
                    descriptors.babel_type() != "ObjectExpression"
                        || descriptors
                            .field_list(self.state.source, Field::Properties)
                            .into_iter()
                            .flatten()
                            .any(|property| {
                                property.babel_type() == "SpreadElement"
                                    || (property.babel_type() == "ObjectProperty"
                                        && property
                                            .field(self.state.source, Field::Key)
                                            .and_then(|key| {
                                                static_property_key(
                                                    self.state.source,
                                                    key,
                                                    property.computed(),
                                                )
                                            })
                                            .is_some_and(|key| key == "require"))
                            })
                } else {
                    true
                }
            }
            ("Object", "assign") => arguments.iter().skip(1).any(|argument| {
                {
                    argument.babel_type() != "ObjectExpression"
                        || argument
                            .field_list(self.state.source, Field::Properties)
                            .into_iter()
                            .flatten()
                            .any(|property| {
                                property.babel_type() == "ObjectProperty"
                                    && property
                                        .field(self.state.source, Field::Key)
                                        .and_then(|key| {
                                            static_property_key(
                                                self.state.source,
                                                key,
                                                property.computed(),
                                            )
                                        })
                                        .is_some_and(|key| key == "require")
                            })
                }
            }),
            _ => false,
        };
        if writes_require {
            self.writes.push(*node);
        }
    }
}

fn is_module_require_target<'a>(state: &SemanticState<'a>, node: Node<'a>) -> bool {
    let node = unwrapped(state.source, node);
    if !matches!(
        node.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    ) {
        return false;
    }
    let key = node
        .field(state.source, Field::Property)
        .and_then(|property| static_property_key(state.source, property, node.computed()));
    let object_is_module = node
        .field(state.source, Field::Object)
        .is_some_and(|object| is_module_object(state, object));
    object_is_module
        && (key.as_ref().is_some_and(|key| key == "require") || (node.computed() && key.is_none()))
}

fn is_module_object<'a>(state: &SemanticState<'a>, node: Node<'a>) -> bool {
    let visited = std::collections::HashSet::new();
    is_module_object_seen(state, node, &visited)
}

fn is_module_object_seen<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    visited: &std::collections::HashSet<String>,
) -> bool {
    let node = unwrapped(state.source, node);
    let Some(name) = node.identifier_name() else {
        return false;
    };
    if name == "module" {
        return state.resolve_binding(&node, "module").is_none()
            && !state.resolution_blocked(&node, "module")
            || state.is_unmodified_commonjs_wrapper_binding(&node, "module");
    }
    let Some(binding) = state.resolve_binding(&node, name) else {
        return false;
    };
    let mut next_visited = visited.clone();
    if !next_visited.insert(state.binding(binding).binding_id.clone()) {
        return false;
    }
    let binding = state.binding(binding);
    !binding.initializers.is_empty()
        && binding
            .initializers
            .iter()
            .all(|initializer| is_module_object_seen(state, initializer.node, &next_visited))
}

/// A static member chain, with the root expression retained for lexical checks.
#[derive(Clone, Debug)]
pub struct MemberChain<'a> {
    pub root: Node<'a>,
    pub members: Vec<JsString>,
}

/// Recover a member chain while preserving dynamic-key uncertainty.
pub fn member_chain<'a>(source: &'a str, node: Option<Node<'a>>) -> Option<MemberChain<'a>> {
    let mut current = unwrapped(source, node?);
    let mut members = Vec::new();

    loop {
        if !matches!(
            current.babel_type(),
            "MemberExpression" | "OptionalMemberExpression"
        ) {
            break;
        }

        let property = current.field(source, Field::Property)?;
        let key = static_property_key(source, property, current.computed())?;
        members.push(key);
        current = unwrapped(source, current.field(source, Field::Object)?);
    }

    members.reverse();
    Some(MemberChain {
        root: current,
        members,
    })
}

/// Recover an unshadowed literal CommonJS `require` and its member path.
pub fn require_origin<'a>(
    state: &SemanticState<'a>,
    node: Option<Node<'a>>,
) -> Option<RequireOrigin<'a>> {
    ordinary_require_origin(state, node)
        .or_else(|| super::bundled_require_origin::bundled_require_origin(state, node))
}

pub(crate) fn ordinary_require_origin<'a>(
    state: &SemanticState<'a>,
    node: Option<Node<'a>>,
) -> Option<RequireOrigin<'a>> {
    let chain = member_chain(state.source, node)?;
    let call = chain.root;
    if call.babel_type() != "CallExpression" {
        return None;
    }

    let callee = call.field(state.source, Field::Callee)?;
    let callee = unwrapped(state.source, callee);
    if callee.identifier_name() != Some("require") {
        return None;
    }

    let binding = state.resolve_binding(&callee, "require");
    if binding.is_some_and(|binding_index| {
        !state.is_unmodified_commonjs_wrapper_binding(&callee, "require")
            && !is_wrapper_require_initializer(state, binding_index, call)
    }) {
        return None;
    }
    if binding.is_none() && state.resolution_blocked(&callee, "require") {
        return None;
    }

    if state
        .ambient_binding_writes
        .get("require")
        .into_iter()
        .flatten()
        .any(|write| effect_timing(call, Some(*write), state, state.source) != EffectTiming::After)
    {
        return None;
    }
    if module_require_writes(state)
        .iter()
        .any(|write| effect_timing(call, Some(*write), state, state.source) != EffectTiming::After)
    {
        return None;
    }

    let arguments = call.field_list(state.source, Field::Arguments);
    let specifier = arguments.first().copied().flatten().and_then(|argument| {
        match read_exact_literal(state.source, argument) {
            Some(ExactLiteral::String(value)) => Some(value),
            _ => None,
        }
    })?;

    Some(RequireOrigin {
        origin: ModuleOrigin {
            resolution_mode: Some(ResolutionMode::Require),
            specifier,
            imported_path: chain.members,
        },
        call,
    })
}

/// Normalize the two CommonJS spellings of `fs/promises`.
pub fn require_exports_identity(
    specifier: &JsString,
    path: &[JsString],
) -> (JsString, Vec<JsString>) {
    let name = specifier
        .strip_prefix("node:")
        .unwrap_or_else(|| specifier.clone());
    if name == "fs/promises" {
        return (name, path.to_vec());
    }
    if name == "fs" && path.first().is_some_and(|key| key == "promises") && path.len() > 1 {
        return (JsString::from("fs/promises"), path[1..].to_vec());
    }
    (name, path.to_vec())
}

/// Mutable builtin origins preserve CommonJS object identity.
pub fn mutable_builtin_origin(
    origin: &ModuleOrigin,
    selected: &[JsString],
) -> Option<(JsString, Vec<JsString>)> {
    let mut path = origin.imported_path.clone();
    path.extend_from_slice(selected);
    if origin.resolution_mode == Some(ResolutionMode::Require) {
        return Some((origin.specifier.clone(), path));
    }

    let specifier = origin
        .specifier
        .strip_prefix("node:")
        .unwrap_or_else(|| origin.specifier.clone());
    let mutable = [
        "fs",
        "fs/promises",
        "net",
        "tls",
        "http",
        "https",
        "child_process",
        "timers",
        "process",
    ]
    .iter()
    .any(|candidate| specifier == *candidate);
    if !mutable {
        return None;
    }
    if path.first().is_some_and(|key| key == "default") {
        path.remove(0);
        return Some((specifier.to_owned(), path));
    }
    if specifier == "process"
        && path
            .first()
            .is_some_and(|key| key == "env" || key == "argv")
    {
        return Some((specifier, path));
    }
    if specifier == "fs" && path.first().is_some_and(|key| key == "promises") {
        return Some((specifier, path));
    }
    None
}

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;

    use oxc_allocator::Allocator;

    use super::*;
    use crate::javascript::ast::AstContext;
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::definitions::collect_definitions;

    fn write_count(source: &str) -> usize {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(&allocator, source, Some("require.js"))
            .expect("parse");
        let context = AstContext::new(parsed.program);
        let ControlFlow::Continue(state) = collect_definitions::<()>(
            context,
            ResolutionMode::Import,
            || ControlFlow::Continue(()),
        ) else {
            panic!("definition collection cancelled");
        };
        module_require_writes(&state).len()
    }

    #[test]
    fn intrinsic_invocation_normalization_covers_call_apply_and_reflect_apply() {
        assert_eq!(
            write_count("Object.defineProperty.call(null, module, 'require', value);"),
            1
        );
        assert_eq!(
            write_count("Reflect.apply(Object.defineProperty, null, [module, 'require', value]);"),
            1
        );
        assert_eq!(
            write_count("Reflect.apply(Object.defineProperty, null, [module, key, value]);"),
            1
        );
        assert_eq!(
            write_count("Reflect.apply(Object.defineProperty, null, unknown);"),
            0
        );
        assert_eq!(
            write_count("Object.defineProperty(module, 'exports', value);"),
            0
        );
    }

    #[test]
    fn require_mutation_index_preserves_descriptor_and_assignment_uncertainty() {
        assert_eq!(
            write_count("Object.defineProperties(module, {require: {value}});"),
            1
        );
        assert_eq!(
            write_count("Object.defineProperties(module, {exports: {value}});"),
            0
        );
        assert_eq!(
            write_count("Object.defineProperties(module, {...descriptors});"),
            1
        );
        assert_eq!(write_count("Object.assign(module, {require: value});"), 1);
        assert_eq!(write_count("Object.assign(module, {exports: value});"), 0);
        assert_eq!(write_count("Object.assign(module, source);"), 1);
        assert_eq!(
            write_count("Reflect.defineProperties(module, {require: {value}});"),
            0
        );
        assert_eq!(write_count("module.require = replacement;"), 1);
        assert_eq!(write_count("module[unknown] = replacement;"), 1);
        assert_eq!(write_count("module.exports = replacement;"), 0);
        assert_eq!(
            write_count("const m = module; Object.defineProperty(m, 'require', value);"),
            1
        );
        assert_eq!(
            write_count("const key = 'require'; Object.defineProperty(module, key, value);"),
            1
        );
    }

    #[test]
    fn module_alias_cycles_are_unknown_without_recursive_stack_growth() {
        assert_eq!(
            write_count("let a = b; let b = a; Object.defineProperty(a, 'require', v);"),
            0
        );
    }
}
