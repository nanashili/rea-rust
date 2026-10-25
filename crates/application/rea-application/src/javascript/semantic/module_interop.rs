//! Semantic facts shared by the Rolldown module interop and require passes.
//!
//! The structural matcher itself lives in `static_analysis::interop`.  This
//! module supplies the lexical facts it needs from one `SemanticState`, while
//! leaving mutation invalidation and runtime module resolution to their
//! owning passes.

use std::collections::{HashMap, HashSet};

use crate::javascript::ast::{Field, Node, NodeKey};
use crate::javascript::static_analysis::interop::{
    INTRINSICS, Template, canonical_roles, identity_function, with_interop_templates,
};
use crate::javascript::static_analysis::semantics::{
    BindingFacts, SemanticReference, StableInitializer, StaticSemantics,
};

use super::ast_values::{ExactLiteral, read_exact_literal, unwrapped};
use super::globals::member_path;
use super::identity_writes::JavaScriptIntrinsicInvocation;
use super::intrinsic_invocation::{expand_invocation_arguments, resolve_intrinsic_invocation};
use super::projection::collect_semantic_projection;
use super::property_paths::{PropertyPath, PropertyPathKey};
use super::reference_role::ReferenceRole;
use super::require_origin::require_origin;
use super::state::{ProjectionKey, SemanticState};
use super::value_types::JsString;

#[derive(Clone, Debug)]
pub struct IntrinsicDependency<'a> {
    pub path: Vec<String>,
    pub captured_at: Option<Node<'a>>,
}

#[derive(Clone, Debug)]
pub struct InteropOrigin<'a> {
    pub origin: super::state::ModuleOrigin,
    pub dependencies: Vec<IntrinsicDependency<'a>>,
    pub default_is_module: bool,
}

#[derive(Clone, Debug)]
struct InteropHelper<'a> {
    dependencies: Vec<IntrinsicDependency<'a>>,
    ready_after: u32,
    identity: bool,
}

/// Stateful module interop analysis for one semantic program.
///
/// The cache is deliberately owned by this object. A helper enters the cache
/// as `None` while it is being proven, so recursive aliases become unknown
/// instead of recursing indefinitely. Mutation records are retained in source
/// order and invalidate only captures that precede the recorded write.
pub struct ModuleInterop<'a, 's> {
    state: &'s SemanticState<'a>,
    global_eval_owner: bool,
    helpers: HashMap<String, Option<InteropHelper<'a>>>,
    origins: HashMap<String, InteropOrigin<'a>>,
    calls: HashMap<NodeKey, InteropOrigin<'a>>,
    invalidated_bindings: HashMap<String, bool>,
    invalidated_calls: HashMap<NodeKey, bool>,
    writes: Vec<(u32, String, PropertyPath)>,
}

/// Construct interop facts for a single semantic state.
pub fn create_module_interop<'a, 's>(state: &'s SemanticState<'a>) -> ModuleInterop<'a, 's> {
    create_module_interop_with_owner(state, false)
}

pub fn create_module_interop_for_global_eval<'a, 's>(
    state: &'s SemanticState<'a>,
) -> ModuleInterop<'a, 's> {
    create_module_interop_with_owner(state, true)
}

fn create_module_interop_with_owner<'a, 's>(
    state: &'s SemanticState<'a>,
    global_eval_owner: bool,
) -> ModuleInterop<'a, 's> {
    ModuleInterop {
        state,
        global_eval_owner,
        helpers: HashMap::new(),
        origins: HashMap::new(),
        calls: HashMap::new(),
        invalidated_bindings: HashMap::new(),
        invalidated_calls: HashMap::new(),
        writes: Vec::new(),
    }
}

impl<'a, 's> ModuleInterop<'a, 's> {
    fn intrinsic_path_for_owner(&self, node: Node<'a>) -> Option<Vec<String>> {
        if self.global_eval_owner {
            global_eval_intrinsic_path(self.state, node)
                .or_else(|| intrinsic_path(self.state, node))
        } else {
            intrinsic_path(self.state, node)
        }
    }
}

/// A limitation shared by the syntax-level interop helpers.
pub const MODULE_INTEROP_LIMITATION: &str = "Module interop is proven only from structurally matched helpers, lexical bindings, literal projections, captured require origins, and explicitly retained intrinsic writes; runtime resolution, arbitrary mutation discovery, and unresolved alias graphs remain unknown.";

fn exact_literal_truthy(value: ExactLiteral) -> bool {
    match value {
        ExactLiteral::String(value) => !value.is_empty(),
        ExactLiteral::Number(value) => value != 0.0,
        ExactLiteral::Boolean(value) => value,
        ExactLiteral::Null => false,
    }
}

fn intrinsic_read_changed<'a>(
    state: &SemanticState<'a>,
    writes: &[(u32, String, PropertyPath)],
    node: Node<'a>,
    path: &[String],
) -> bool {
    let capture = captured_intrinsic_capture(state, node).unwrap_or(node);
    let capture_scope = mutation_scope(state, capture);
    let method = path.last().map(String::as_str);
    let invocation_method = matches!(method, Some("bind" | "call" | "apply"));
    let requested_path = path
        .iter()
        .cloned()
        .map(JsString::from)
        .map(PropertyPathKey::String)
        .collect::<PropertyPath>();
    writes.iter().any(|(offset, scope, write_path)| {
        *offset < state.context.start(&capture)
            && (scope == &capture_scope || scope == "intrinsic")
            && (property_path_covers(&requested_path, write_path)
                || (invocation_method
                    && property_path_covers(
                        &expected_intrinsic_path(&["Function", "prototype", method.unwrap_or("")])
                            .into_iter()
                            .map(JsString::from)
                            .map(PropertyPathKey::String)
                            .collect::<PropertyPath>(),
                        write_path,
                    )))
    })
}

fn property_path_covers(requested: &[PropertyPathKey], written: &[PropertyPathKey]) -> bool {
    written.len() <= requested.len()
        && written
            .iter()
            .zip(requested)
            .all(|(written, requested)| match written {
                PropertyPathKey::Wildcard => true,
                PropertyPathKey::String(value) => {
                    matches!(requested, PropertyPathKey::String(name) if name == value)
                        || matches!(requested, PropertyPathKey::Number(index) if index.to_string() == *value)
                }
                PropertyPathKey::Number(value) => {
                    matches!(requested, PropertyPathKey::String(name) if name == &value.to_string())
                        || matches!(requested, PropertyPathKey::Number(index) if index == value)
                }
                PropertyPathKey::Selection(_) => false,
            })
}

fn mutation_scope<'a>(state: &SemanticState<'a>, node: Node<'a>) -> String {
    state
        .scope_for_node(&node)
        .map(|scope| state.scope(scope).scope_id.clone())
        .unwrap_or_else(|| "intrinsic".to_owned())
}

fn captured_intrinsic_capture<'a>(state: &SemanticState<'a>, node: Node<'a>) -> Option<Node<'a>> {
    intrinsic_path(state, node)?;
    let mut current = node;
    let mut captured_at = node;
    let mut visited = HashSet::new();

    loop {
        let chain = super::require_origin::member_chain(state.source, Some(current))?;
        let Some(name) = chain.root.identifier_name() else {
            return None;
        };
        let Some(binding) = state.resolve_binding(&chain.root, name) else {
            return Some(captured_at);
        };
        if !visited.insert(binding) {
            return None;
        }
        let initializer = state.stable_initializer(binding)?;
        if state.context.end(&initializer.node) >= state.context.start(&chain.root) {
            return None;
        }
        if chain.members.is_empty() {
            captured_at = initializer.node;
        }
        current = initializer.node;
    }
}

fn expected_intrinsic_path(parts: &[&str]) -> Vec<String> {
    std::iter::once("intrinsic")
        .chain(parts.iter().copied())
        .map(str::to_owned)
        .collect()
}

fn literal_array_arguments<'a>(
    state: &SemanticState<'a>,
    node: Option<Node<'a>>,
) -> Option<Vec<Node<'a>>> {
    let array = unwrapped(state.source, node?);
    if array.babel_type() != "ArrayExpression" {
        return None;
    }
    let elements = array
        .field_list(state.source, Field::Elements)
        .into_iter()
        .collect::<Option<Vec<_>>>()?;
    let expanded = expand_invocation_arguments(state.source, &elements);
    expanded.iter().all(Node::is_expression).then_some(expanded)
}

/// Recover an intrinsic path from an unshadowed global or a stable alias.
pub fn intrinsic_path<'a>(state: &SemanticState<'a>, node: Node<'a>) -> Option<Vec<String>> {
    let mut current = node;
    let mut suffix = Vec::new();
    let mut visited = HashSet::new();

    loop {
        let (root, members) = member_path(state.source, current);
        if members.iter().any(Option::is_none) {
            return None;
        }
        let members = members
            .into_iter()
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .map(|segment| segment.try_to_string().ok())
            .collect::<Option<Vec<_>>>()?;
        suffix.splice(0..0, members);

        if ["Object", "Function", "Reflect"]
            .into_iter()
            .any(|name| state.is_unshadowed_global(&root, name))
        {
            let name = root.identifier_name()?.to_owned();
            return Some(
                ["intrinsic", name.as_str()]
                    .into_iter()
                    .map(str::to_owned)
                    .chain(suffix)
                    .collect(),
            );
        }
        if ["globalThis", "global", "window", "self"]
            .into_iter()
            .any(|name| state.is_unshadowed_global(&root, name))
        {
            let prefix = if root.identifier_name() == Some("eval") {
                ["intrinsic", "eval"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            } else {
                vec!["intrinsic".to_owned()]
            };
            return Some(prefix.into_iter().chain(suffix).collect());
        }

        let name = root.identifier_name()?;
        let binding = state.resolve_binding(&root, name)?;
        if !visited.insert(binding) {
            return None;
        }
        let initializer =
            state.bindings[binding]
                .initializers
                .iter()
                .rev()
                .find(|initializer| {
                    state.context.end(&initializer.node) < state.context.start(&current)
                        && !state
                            .conditionally_skipped
                            .contains(&initializer.node.key())
                })?;
        let projection = initializer
            .projection
            .iter()
            .map(|key| match key {
                super::state::ProjectionKey::Name(name) => name.try_to_string().ok(),
                super::state::ProjectionKey::Index(index) => Some(index.to_string()),
                super::state::ProjectionKey::Dynamic => None,
            })
            .collect::<Option<Vec<_>>>()?;
        suffix.splice(0..0, projection);
        current = initializer.node;
    }
}

/// Use the ambient observer's canonical global-eval owner path.
///
/// The ordinary intrinsic path deliberately excludes `eval`. The ambient
/// observer needs the receiver identity used by its TypeScript owner, where
/// global `eval` is represented as `global.eval` before call/apply
/// normalization.
fn global_eval_intrinsic_path<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
) -> Option<Vec<String>> {
    let mut current = node;
    let mut suffix = Vec::new();
    let mut visited = HashSet::new();

    loop {
        let (root, members) = member_path(state.source, current);
        let members = members
            .into_iter()
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .map(|segment| segment.try_to_string().ok())
            .collect::<Option<Vec<_>>>()?;
        suffix.splice(0..0, members);

        if state.is_unshadowed_global(&root, "eval") {
            return Some(
                ["intrinsic", "global", "eval"]
                    .into_iter()
                    .map(str::to_owned)
                    .chain(suffix)
                    .collect(),
            );
        }
        if ["globalThis", "global", "window", "self"]
            .into_iter()
            .any(|name| state.is_unshadowed_global(&root, name))
        {
            if suffix.first().map(String::as_str) != Some("eval") {
                return None;
            }
            return Some(
                ["intrinsic", "global", "eval"]
                    .into_iter()
                    .map(str::to_owned)
                    .chain(suffix.into_iter().skip(1))
                    .collect(),
            );
        }

        let name = root.identifier_name()?;
        let binding = state.resolve_binding(&root, name)?;
        if !visited.insert(binding) {
            return None;
        }
        let initializer =
            state.bindings[binding]
                .initializers
                .iter()
                .rev()
                .find(|initializer| {
                    state.context.end(&initializer.node) < state.context.start(&current)
                        && !state
                            .conditionally_skipped
                            .contains(&initializer.node.key())
                })?;
        let projection = initializer
            .projection
            .iter()
            .map(|key| match key {
                super::state::ProjectionKey::Name(name) => name.try_to_string().ok(),
                super::state::ProjectionKey::Index(index) => Some(index.to_string()),
                super::state::ProjectionKey::Dynamic => None,
            })
            .collect::<Option<Vec<_>>>()?;
        suffix.splice(0..0, projection);
        current = initializer.node;
    }
}

/// Resolve a string literal or a stable, unprojected string alias.
pub fn static_string<'a>(state: &SemanticState<'a>, node: Option<Node<'a>>) -> Option<JsString> {
    let mut current = unwrapped(state.source, node?);
    let mut visited = HashSet::new();
    loop {
        if let Some(ExactLiteral::String(value)) = read_exact_literal(state.source, current) {
            return Some(value);
        }
        let name = current.identifier_name()?;
        let binding = state.resolve_binding(&current, name)?;
        if !visited.insert(binding) {
            return None;
        }
        let initializer = state.stable_initializer(binding)?;
        if !initializer.projection.is_empty() {
            return None;
        }
        if state.context.end(&initializer.node) >= state.context.start(&current) {
            return None;
        }
        current = unwrapped(state.source, initializer.node);
    }
}

/// Prove that a value is freshly allocated at the examined source site.
pub fn is_fresh_object<'a>(state: &SemanticState<'a>, node: Node<'a>) -> bool {
    let mut current = unwrapped(state.source, node);
    let mut visited = HashSet::new();
    loop {
        if matches!(
            current.babel_type(),
            "ObjectExpression"
                | "ArrayExpression"
                | "FunctionExpression"
                | "ArrowFunctionExpression"
                | "FunctionDeclaration"
                | "ClassExpression"
                | "ClassDeclaration"
                | "RegExpLiteral"
        ) {
            return true;
        }
        let Some(name) = current.identifier_name() else {
            return false;
        };
        let Some(binding) = state.resolve_binding(&current, name) else {
            return false;
        };
        if !visited.insert(binding) {
            return false;
        }
        let Some(initializer) = state.stable_initializer(binding) else {
            return false;
        };
        if !initializer.projection.is_empty()
            || (initializer.node.babel_type() != "FunctionDeclaration"
                && state.context.end(&initializer.node) >= state.context.start(&current))
        {
            return false;
        }
        current = unwrapped(state.source, initializer.node);
    }
}

/// Return an expression's first positional argument when it exists.
pub fn argument<'a>(state: &SemanticState<'a>, call: Node<'a>, index: usize) -> Option<Node<'a>> {
    call.field_list(state.source, Field::Arguments)
        .get(index)
        .copied()
        .flatten()
}

pub(crate) struct StateFacts<'a, 's> {
    state: &'s SemanticState<'a>,
    facts: HashMap<String, BindingFacts>,
}

impl<'a, 's> StateFacts<'a, 's> {
    pub(crate) fn new(state: &'s SemanticState<'a>) -> Self {
        let facts = state
            .bindings
            .iter()
            .map(|binding| {
                (
                    binding.binding_id.clone(),
                    BindingFacts {
                        binding_id: binding.binding_id.clone(),
                        name: binding.name.clone(),
                        mutable: binding.mutable,
                        scope_kind: state
                            .scopes_by_id
                            .get(&binding.scope_id)
                            .map(|index| state.scopes[*index].kind.as_str().to_owned()),
                        definitions: binding.definitions.len(),
                        initializers: binding.initializers.len(),
                    },
                )
            })
            .collect();
        Self { state, facts }
    }
}

impl<'a, 's> StaticSemantics<'a> for StateFacts<'a, 's> {
    fn binding(&self, identifier: &Node<'a>) -> Option<&BindingFacts> {
        let name = identifier.identifier_name()?;
        let id = self.state.resolve_binding(identifier, name)?;
        self.facts.get(&self.state.bindings[id].binding_id)
    }

    fn binding_by_id(&self, id: &str) -> Option<&BindingFacts> {
        self.facts.get(id)
    }

    fn stable_initializer(&self, id: &str) -> Option<StableInitializer<'a>> {
        let index = self.state.bindings_by_id.get(id)?;
        let initializer = self.state.stable_initializer(*index)?;
        Some(StableInitializer {
            node: initializer.node,
            projection_len: initializer.projection.len(),
        })
    }

    fn parent(&self, node: &Node<'a>) -> Option<Node<'a>> {
        self.state.parent_of(node)
    }

    fn is_module(&self) -> bool {
        !self.state.script
    }

    fn references(&self) -> Vec<SemanticReference> {
        let (_, references) = collect_semantic_projection(self.state);
        references
            .into_iter()
            .map(|reference| SemanticReference {
                name: reference.name,
                binding_id: reference.binding_id,
                role: match reference.role {
                    ReferenceRole::Read => "read",
                    ReferenceRole::Write => "write",
                    ReferenceRole::Export => "export",
                }
                .to_owned(),
                location: reference.location.into(),
                resolution: reference.resolution.to_owned(),
            })
            .collect()
    }
}

impl<'a, 's> ModuleInterop<'a, 's> {
    fn binding(&self, id: &str) -> Option<usize> {
        self.state.bindings_by_id.get(id).copied()
    }

    fn unprojected_initializer(&self, id: &str) -> Option<Node<'a>> {
        let binding = self.binding(id)?;
        let initializer = self.state.stable_initializer(binding)?;
        initializer
            .projection
            .is_empty()
            .then_some(initializer.node)
    }

    fn captured_intrinsic(&self, node: Node<'a>) -> Option<IntrinsicDependency<'a>> {
        let path = self.intrinsic_path_for_owner(node)?;
        let mut current = node;
        let mut captured_at = node;
        let mut visited = HashSet::new();
        loop {
            let chain = super::require_origin::member_chain(self.state.source, Some(current))?;
            let Some(name) = chain.root.identifier_name() else {
                return None;
            };
            let Some(binding) = self.state.resolve_binding(&chain.root, name) else {
                return Some(IntrinsicDependency {
                    path,
                    captured_at: Some(captured_at),
                });
            };
            let binding_id = &self.state.binding(binding).binding_id;
            if !visited.insert(binding_id.clone()) {
                return None;
            }
            let initializer = self.state.stable_initializer(binding)?;
            if self.state.context.end(&initializer.node) >= self.state.context.start(&chain.root) {
                return None;
            }
            if chain.members.is_empty() {
                captured_at = initializer.node;
            }
            current = initializer.node;
        }
    }

    fn helper_proof(&mut self, binding_id: &str) -> Option<InteropHelper<'a>> {
        if let Some(cached) = self.helpers.get(binding_id) {
            return cached.clone();
        }
        self.helpers.insert(binding_id.to_owned(), None);

        let binding = self.state.binding(self.binding(binding_id)?);
        let scope = self.state.scopes_by_id.get(&binding.scope_id)?;
        if self.state.scopes[*scope].kind.as_str() != "program" {
            return None;
        }
        let wrapper = self.unprojected_initializer(binding_id)?;
        let facts = StateFacts::new(self.state);
        if identity_function(&self.state.context, &wrapper, &facts) {
            let proof = InteropHelper {
                dependencies: Vec::new(),
                ready_after: if wrapper.babel_type() == "FunctionDeclaration" {
                    0
                } else {
                    self.state.context.end(&wrapper)
                },
                identity: true,
            };
            self.helpers
                .insert(binding_id.to_owned(), Some(proof.clone()));
            return Some(proof);
        }

        let proof = with_interop_templates(|templates| {
            let roles = canonical_roles(
                &self.state.context,
                wrapper,
                templates,
                Template::ToEsm,
                &facts,
            )?;
            let copy_id = roles.get("__copyProps")?;
            let copy = self.unprojected_initializer(copy_id)?;
            let copy_roles = canonical_roles(
                &self.state.context,
                copy,
                templates,
                Template::CopyProps,
                &facts,
            )?;
            let mut dependencies = Vec::new();
            let mut ready_after = self
                .state
                .context
                .end(&wrapper)
                .max(self.state.context.end(&copy));
            for role_map in [&roles, &copy_roles] {
                for (role, id) in role_map {
                    let Some((_, expected)) = INTRINSICS
                        .iter()
                        .find(|(intrinsic_role, _)| *intrinsic_role == role.as_str())
                    else {
                        continue;
                    };
                    let initializer = self.unprojected_initializer(id)?;
                    let captured = self.captured_intrinsic(initializer)?;
                    if captured.path != expected_intrinsic_path(expected) {
                        return None;
                    }
                    ready_after = ready_after.max(self.state.context.end(&initializer));
                    dependencies.push(captured.clone());
                    if role == "__hasOwnProp" {
                        dependencies.push(IntrinsicDependency {
                            path: [captured.path.clone(), vec!["call".to_owned()]].concat(),
                            captured_at: captured.captured_at,
                        });
                    }
                }
            }
            dependencies.push(IntrinsicDependency {
                path: vec!["intrinsic", "Function", "prototype", "bind"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                captured_at: None,
            });
            dependencies.push(IntrinsicDependency {
                path: vec!["intrinsic", "Function", "prototype", "call"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                captured_at: None,
            });
            Some(InteropHelper {
                dependencies,
                ready_after,
                identity: false,
            })
        })?;
        self.helpers
            .insert(binding_id.to_owned(), Some(proof.clone()));
        Some(proof)
    }

    fn proven_call(
        &mut self,
        node: Node<'a>,
    ) -> Option<(Node<'a>, bool, Vec<IntrinsicDependency<'a>>)> {
        if node.babel_type() != "CallExpression" {
            return None;
        }
        let callee = node.field(self.state.source, Field::Callee)?;
        let name = callee.identifier_name()?;
        let binding = self.state.resolve_binding(&callee, name)?;
        let proof = self.helper_proof(&self.state.binding(binding).binding_id)?;
        if self.state.context.start(&node) <= proof.ready_after {
            return None;
        }
        let input = argument(self.state, node, 0)?;
        let mode = argument(self.state, node, 1);
        let default_is_module = if proof.identity {
            false
        } else {
            match mode {
                None => false,
                Some(mode) => exact_literal_truthy(read_exact_literal(self.state.source, mode)?),
            }
        };
        let arguments = node.field_list(self.state.source, Field::Arguments);
        if arguments.len() > 2 {
            return None;
        }
        let dependencies = proof
            .dependencies
            .into_iter()
            .map(|mut dependency| {
                if dependency.captured_at.is_none() {
                    dependency.captured_at = Some(node);
                }
                dependency
            })
            .collect();
        Some((input, default_is_module, dependencies))
    }

    pub fn call_origin(&mut self, node: Node<'a>) -> Option<InteropOrigin<'a>> {
        if let Some(cached) = self.calls.get(&node.key()) {
            return Some(cached.clone());
        }
        let chain = super::require_origin::member_chain(self.state.source, Some(node))?;
        let (input, default_is_module, dependencies) = self.proven_call(chain.root)?;
        let required = require_origin(self.state, Some(input))?.origin;
        if !required.imported_path.is_empty()
            || (chain
                .members
                .first()
                .is_some_and(|member| member == "default")
                && !default_is_module)
        {
            return None;
        }
        let result = InteropOrigin {
            origin: super::state::ModuleOrigin {
                imported_path: chain.members,
                ..required
            },
            dependencies,
            default_is_module,
        };
        self.calls.insert(node.key(), result.clone());
        Some(result)
    }

    pub fn origin(&mut self, binding_id: &str) -> Option<super::state::ModuleOrigin> {
        if let Some(cached) = self.origins.get(binding_id) {
            return Some(cached.origin.clone());
        }
        let binding = self.binding(binding_id)?;
        let binding_record = self.state.binding(binding).clone();
        let result = if let Some(initializer) = self.state.stable_initializer(binding) {
            if !initializer
                .projection
                .iter()
                .all(|key| matches!(key, ProjectionKey::Name(_)))
            {
                return None;
            }
            let mut result = self.call_origin(initializer.node)?;
            if result.origin.imported_path.is_empty()
                && initializer.projection.first().is_some_and(
                    |key| matches!(key, ProjectionKey::Name(name) if name == "default"),
                )
                && !result.default_is_module
            {
                return None;
            }
            result
                .origin
                .imported_path
                .extend(initializer.projection.iter().filter_map(|key| match key {
                    ProjectionKey::Name(name) => Some(name.clone()),
                    _ => None,
                }));
            result
        } else {
            let [initial, converted] = binding_record.initializers.as_slice() else {
                return None;
            };
            if binding_record.definitions.len() != 2
                || binding_record.definitions[0].kind != super::state::DefinitionKind::Variable
                || binding_record.definitions[1].kind != super::state::DefinitionKind::Assignment
                || !initial.projection.is_empty()
                || !converted.projection.is_empty()
                || self
                    .state
                    .conditionally_skipped
                    .contains(&initial.node.key())
            {
                return None;
            }
            let assignment = self.state.parent_of(&converted.node)?;
            if assignment.babel_type() != "AssignmentExpression"
                || assignment.operator() != Some("=")
                || assignment
                    .field(self.state.source, Field::Right)
                    .map(|node| node.key())
                    != Some(converted.node.key())
            {
                return None;
            }
            let target = assignment
                .field(self.state.source, Field::Left)
                .map(|node| unwrapped(self.state.source, node))?;
            if target.identifier_name() != Some(binding_record.name.as_str())
                || self.state.resolve_binding(&target, &binding_record.name) != Some(binding)
            {
                return None;
            }
            let declaration = self.state.parent_of(&initial.node)?;
            let declaration_statement = self.state.parent_of(&declaration)?;
            let statement = self.state.parent_of(&assignment)?;
            if declaration.babel_type() != "VariableDeclarator"
                || declaration_statement.babel_type() != "VariableDeclaration"
                || statement.babel_type() != "ExpressionStatement"
                || self.state.parent_of(&statement).map(|node| node.key())
                    != self
                        .state
                        .parent_of(&declaration_statement)
                        .map(|node| node.key())
                || self.state.context.start(&initial.node)
                    >= self.state.context.start(&converted.node)
            {
                return None;
            }
            let converted_input = argument(self.state, converted.node, 0)?;
            if converted_input.identifier_name() != Some(binding_record.name.as_str())
                || self
                    .state
                    .resolve_binding(&converted_input, &binding_record.name)
                    != Some(binding)
            {
                return None;
            }
            let required = require_origin(self.state, Some(initial.node))?.origin;
            if !required.imported_path.is_empty() {
                return None;
            }
            let (_, default_is_module, dependencies) = self.proven_call(converted.node)?;
            InteropOrigin {
                origin: required,
                dependencies,
                default_is_module,
            }
        };
        self.origins.insert(binding_id.to_owned(), result.clone());
        Some(result.origin)
    }

    pub fn retain_write(&mut self, node: Node<'a>, path: &[PropertyPathKey]) {
        let canonical_path = if path.first().is_some_and(
            |key| matches!(key, PropertyPathKey::String(value) if value == "opaque-intrinsic"),
        ) {
            vec![PropertyPathKey::String(("intrinsic").into())]
        } else {
            path.to_vec()
        };
        self.writes.push((
            self.state.context.start(&node),
            mutation_scope(self.state, node),
            canonical_path,
        ));
    }

    /// Resolve call/apply/Reflect.apply syntax from the canonical intrinsic
    /// path owner. Bound aliases remain unknown until their owner supplies a
    /// bound-value proof.
    pub fn intrinsic_invocation(
        &mut self,
        node: Node<'a>,
    ) -> Option<JavaScriptIntrinsicInvocation<'a>> {
        let source = self.state.source;
        let writes = self.writes.clone();
        resolve_intrinsic_invocation(
            source,
            node,
            |callee| self.intrinsic_path_for_owner(callee),
            |callee| self.bound_intrinsic(callee),
            |callee, path| intrinsic_read_changed(self.state, &writes, callee, path),
        )
    }

    fn bound_intrinsic(&self, node: Node<'a>) -> Option<JavaScriptIntrinsicInvocation<'a>> {
        let mut current = unwrapped(self.state.source, node);
        let mut prefixes = Vec::<Vec<Node<'a>>>::new();
        let mut visited = HashSet::new();

        loop {
            if let Some(path) = self.intrinsic_path_for_owner(current) {
                let mut receiver = None;
                let mut arguments = Vec::new();
                for group in prefixes.iter().rev() {
                    receiver = receiver.or_else(|| group.first().copied());
                    arguments.extend(group.iter().skip(1).copied());
                }
                return Some(JavaScriptIntrinsicInvocation {
                    kind: super::identity_writes::IntrinsicInvocationKind::Known,
                    receiver,
                    path,
                    arguments: Some(arguments),
                });
            }

            if let Some(name) = current.identifier_name() {
                let binding = self.state.resolve_binding(&current, name)?;
                if !visited.insert(binding) {
                    return None;
                }
                let initializer = self.state.stable_initializer(binding)?;
                if self.state.context.end(&initializer.node) >= self.state.context.start(&current)
                    || !initializer.projection.is_empty()
                {
                    return None;
                }
                current = unwrapped(self.state.source, initializer.node);
                continue;
            }

            if current.babel_type() != "CallExpression" {
                return None;
            }
            let callee = current.field(self.state.source, Field::Callee)?;
            let method = callee
                .field(self.state.source, Field::Property)
                .and_then(|property| {
                    super::ast_values::static_property_key(
                        self.state.source,
                        property,
                        callee.computed(),
                    )
                })?;
            let raw_arguments = current
                .field_list(self.state.source, Field::Arguments)
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            let (target, arguments) = if method == "bind" {
                let target = callee.field(self.state.source, Field::Object)?;
                let arguments = super::intrinsic_invocation::expand_invocation_arguments(
                    self.state.source,
                    &raw_arguments,
                );
                (target, arguments)
            } else {
                let owner = callee.field(self.state.source, Field::Object)?;
                let owner_path = self.intrinsic_path_for_owner(owner)?;
                let (target, arguments) = if owner_path
                    == expected_intrinsic_path(&["Function", "prototype", "bind"])
                {
                    let target = raw_arguments.first().copied()?;
                    let arguments = if method == "call" {
                        raw_arguments.into_iter().skip(1).collect()
                    } else if method == "apply" {
                        let packed = unwrapped(self.state.source, raw_arguments.get(1).copied()?);
                        if packed.babel_type() != "ArrayExpression" {
                            return None;
                        }
                        packed
                            .field_list(self.state.source, Field::Elements)
                            .into_iter()
                            .collect::<Option<Vec<_>>>()?
                    } else {
                        return None;
                    };
                    (target, arguments)
                } else if method == "apply" && owner_path == expected_intrinsic_path(&["Reflect"]) {
                    let packed =
                        literal_array_arguments(self.state, raw_arguments.get(2).copied())?;
                    let target = packed.first().copied()?;
                    let arguments = packed.into_iter().skip(1).collect();
                    (target, arguments)
                } else {
                    return None;
                };
                (target, arguments)
            };
            if arguments
                .iter()
                .any(|argument| argument.babel_type() == "SpreadElement")
            {
                let path = self.intrinsic_path_for_owner(target)?;
                return Some(JavaScriptIntrinsicInvocation {
                    kind: super::identity_writes::IntrinsicInvocationKind::Opaque,
                    receiver: None,
                    path,
                    arguments: None,
                });
            }
            prefixes.push(arguments);
            current = unwrapped(self.state.source, target);
        }
    }

    pub fn invalidated(&mut self, binding_id: &str) -> bool {
        if let Some(cached) = self.invalidated_bindings.get(binding_id) {
            return *cached;
        }
        let result = self
            .origins
            .get(binding_id)
            .is_some_and(|origin| self.is_invalidated(origin));
        self.invalidated_bindings
            .insert(binding_id.to_owned(), result);
        result
    }

    pub fn invalidated_call(&mut self, node: Node<'a>) -> bool {
        if let Some(cached) = self.invalidated_calls.get(&node.key()) {
            return *cached;
        }
        let result = self
            .calls
            .get(&node.key())
            .is_some_and(|origin| self.is_invalidated(origin));
        self.invalidated_calls.insert(node.key(), result);
        result
    }

    fn is_invalidated(&self, origin: &InteropOrigin<'a>) -> bool {
        origin.dependencies.iter().any(|dependency| {
            let Some(captured_at) = dependency.captured_at else {
                return true;
            };
            let capture_scope = mutation_scope(self.state, captured_at);
            self.writes.iter().any(|(offset, scope, path)| {
                *offset < self.state.context.start(&captured_at)
                    && (scope == &capture_scope || scope == "intrinsic")
                    && property_path_covers(
                        &dependency
                            .path
                            .iter()
                            .cloned()
                            .map(JsString::from)
                            .map(PropertyPathKey::String)
                            .collect::<PropertyPath>(),
                        path,
                    )
            })
        })
    }
}
