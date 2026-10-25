//! Port of `createState` and `collectDefinitionsSteps` from
//! `javascriptSemanticAnalysis.ts`: REA's scope list, scope/binding IDs and
//! binding records, built in one Babel-order DFS plus the post passes
//! (prototype uncertainty, queued writes, parameter copies).
//!
//! Not run here (later packages own them): `collectSemanticCallable`
//! (projection), and `indexSemanticOpaqueEffects` (opaque effects). The
//! direct-`eval` candidates it consumes are queued in
//! [`SemanticState::opaque_candidates`]; neither changes scopes or bindings.

use std::cell::RefCell;
use std::ops::ControlFlow;

use crate::javascript::ast::{AstContext, AstVisitor, Field, Node, NodeMap, NodeSet, traverse};

use super::ast_values::{
    is_call, is_class, is_function, is_identifier_named, is_member, object_pattern_keys,
    runtime_function_parameters, static_property_key, unwrapped, write_site_target, write_targets,
};
use super::evaluation_order::{IterationCardinality, branch_may_be_skipped, iteration_cardinality};
use super::globals::{GLOBAL_EVAL_ROOTS, is_unmodified_global_reference};
use super::reference_role::reference_role;
use super::state::{
    BindingState, CopyKind, DeclarationKind, Definition, DefinitionKind, Initializer, InsertionMap,
    ModuleOrigin, ProjectionKey, ReferenceInitializer, ResolutionMode, ScopeIndex, ScopeKind,
    ScopeState, SemanticState, binding_id, scope_id,
};
use super::value_types::JsString;

/// Queued writes are bound in batches of this size between checkpoints.
const WRITE_CHECKPOINT_INTERVAL: usize = 64;

/// `createState` followed by `collectDefinitionsSteps`. `checkpoint` runs
/// where the TS generator yields; `Break` cancels and is returned.
pub fn collect_definitions<'a, B>(
    context: AstContext<'a>,
    static_import_resolution_mode: ResolutionMode,
    mut checkpoint: impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, SemanticState<'a>> {
    let mut state = create_state(context, static_import_resolution_mode);
    collect(&mut state, &mut checkpoint)?;
    ControlFlow::Continue(state)
}

fn create_state<'a>(context: AstContext<'a>, mode: ResolutionMode) -> SemanticState<'a> {
    let program = context.root();
    let source = context.source();
    let root_id = scope_id(
        ScopeKind::Program,
        context.start(&program),
        context.end(&program),
    );
    let root = ScopeState {
        scope_id: root_id.clone(),
        parent_scope_id: None,
        kind: ScopeKind::Program,
        location: context.range(&program),
        bindings_complete: true,
        bindings: InsertionMap::default(),
        dynamic_with_statement: None,
    };
    let mut scopes_by_id = InsertionMap::default();
    scopes_by_id.set(root_id, 0);
    let mut scope_by_node = NodeMap::default();
    scope_by_node.insert(program.key(), 0);
    let script = !context.program().source_type.is_module();
    SemanticState {
        context,
        source,
        program,
        script,
        static_import_resolution_mode: mode,
        parents: NodeMap::default(),
        scopes: vec![root],
        scopes_by_id,
        scope_by_node: RefCell::new(scope_by_node),
        bindings: Vec::new(),
        bindings_by_id: InsertionMap::default(),
        binding_writes: InsertionMap::default(),
        ambient_binding_writes: InsertionMap::default(),
        ambient_writes: super::property_paths::SemanticPropertyPathCoverage::default(),
        ambient_escapes: super::property_paths::SemanticPropertyPathCoverage::default(),
        ambient_write_effects: Vec::new(),
        required_module_effects: super::state::RequiredModuleEffects::default(),
        returned_reference_widenings: RefCell::new(Vec::new()),
        conditionally_skipped: NodeSet::default(),
        prototype_require_mutation_observed: Some(false),
        prototype_enumeration_may_affect: Some(false),
        may_reference_global_eval: false,
        opaque_candidates: Vec::new(),
        global_eval_sites_cache: RefCell::new(None),
        getter_resource_limits: RefCell::new(Vec::new()),
        value_resource_limits: RefCell::new(Vec::new()),
        value_caches: RefCell::new(super::values::ValueCaches::default()),
        module_require_writes: RefCell::new(super::state::ModuleRequireWritesCache::Empty),
        bundled_require_proofs: RefCell::new(
            super::bundled_require_origin::BundledRequireProofCache::default(),
        ),
        next_initializer_id: 1,
    }
}

struct QueuedWrite<'a> {
    node: Node<'a>,
    scope: ScopeIndex,
    conditionally_skipped: bool,
}

struct FunctionBody<'a> {
    body: Node<'a>,
    scope: ScopeIndex,
    parameters: Vec<Node<'a>>,
}

struct Definitions<'s, 'a> {
    state: &'s mut SemanticState<'a>,
    stack: Vec<ScopeIndex>,
    opened: NodeMap<usize>,
    assignments: Vec<QueuedWrite<'a>>,
    function_bodies: Vec<FunctionBody<'a>>,
    needs_prototype_facts: bool,
}

impl<'a> AstVisitor<'a> for Definitions<'_, 'a> {
    fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
        let source = self.state.source;
        if let Some(parent) = parent {
            self.state.parents.insert(node.key(), *parent);
        }
        if matches!(
            node.babel_type(),
            "WithStatement" | "ForInStatement" | "ForOfStatement"
        ) {
            self.needs_prototype_facts = true;
        }
        let mut parent_scope = *self.stack.last().expect("semantic scope");
        if let Some(parent) = parent
            && matches!(parent.babel_type(), "ObjectMethod" | "ClassMethod")
            && parent.computed()
            && is_field(source, parent, Field::Key, node)
            && let Some(key_scope) = self.state.parent_scope(parent_scope)
        {
            // A computed method key is evaluated before entering the
            // method's parameter and body environments.
            self.stack.push(key_scope);
            self.opened.insert(node.key(), 1);
            parent_scope = key_scope;
        }
        if let Some(parent) = parent
            && parent.babel_type() == "WithStatement"
            && is_field(source, parent, Field::Body, node)
        {
            let context = &self.state.context;
            let id = format!(
                "{}:with",
                scope_id(ScopeKind::Block, context.start(parent), context.end(parent))
            );
            let dynamic = ScopeState {
                scope_id: id.clone(),
                parent_scope_id: Some(self.state.scopes[parent_scope].scope_id.clone()),
                kind: ScopeKind::Block,
                location: context.range(parent),
                bindings_complete: false,
                bindings: InsertionMap::default(),
                dynamic_with_statement: Some(*parent),
            };
            let index = push_scope(self.state, dynamic);
            self.stack.push(index);
            self.opened.insert(node.key(), 1);
            parent_scope = index;
        }
        bind_outer_declaration(self.state, node, parent_scope);
        let nested = nested_scope(self.state, node, parent, parent_scope);
        if let Some(nested) = nested {
            self.stack.push(nested);
            *self.opened.entry(node.key()).or_insert(0) += 1;
            if let Some(parent) = parent
                && node.babel_type() == "BlockStatement"
                && is_function(parent)
            {
                self.function_bodies.push(FunctionBody {
                    body: *node,
                    scope: nested,
                    parameters: runtime_function_parameters(source, parent),
                });
            }
        }
        let scope = *self.stack.last().expect("semantic scope");
        // Other nodes inherit the nearest boundary through their parents.
        if parent.is_none() || self.opened.contains_key(&node.key()) {
            self.state.scope_by_node.get_mut().insert(node.key(), scope);
        }
        bind_inner_declaration(self.state, node, parent, scope);
        // Every supported global eval origin starts with one of these names.
        if node
            .identifier_name()
            .is_some_and(|name| GLOBAL_EVAL_ROOTS.contains(&name))
        {
            self.state.may_reference_global_eval = true;
        }
        if node.babel_type() == "CallExpression"
            && node
                .field(source, Field::Callee)
                .is_some_and(|callee| is_identifier_named(&unwrapped(source, callee), "eval"))
        {
            let id = self.state.scopes[scope].scope_id.clone();
            self.state.opaque_candidates.push((*node, id));
        }
        if node.babel_type() == "VariableDeclarator"
            && let Some(init) = node.field(source, Field::Init)
            && let Some(parent) = parent
            && parent.babel_type() == "VariableDeclaration"
            && parent.declaration_kind() == Some("var")
            && write_may_be_skipped(source, node, ancestors)
        {
            self.state.conditionally_skipped.insert(init.key());
        }
        let is_loop = matches!(node.babel_type(), "ForOfStatement" | "ForInStatement");
        if is_loop
            || matches!(
                node.babel_type(),
                "AssignmentExpression" | "UpdateExpression"
            )
        {
            self.assignments.push(QueuedWrite {
                node: *node,
                scope,
                conditionally_skipped: is_loop || write_may_be_skipped(source, node, ancestors),
            });
        }
    }

    fn exit(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>) {
        for _ in 0..self.opened.get(&node.key()).copied().unwrap_or(0) {
            self.stack.pop();
        }
    }
}

fn collect<'a, B>(
    state: &mut SemanticState<'a>,
    checkpoint: &mut impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B> {
    let source = state.source;
    let root = state.program;
    let mut visitor = Definitions {
        state,
        stack: vec![0],
        opened: NodeMap::default(),
        assignments: Vec::new(),
        function_bodies: Vec::new(),
        needs_prototype_facts: false,
    };
    traverse(root, source, &mut visitor, &mut *checkpoint)?;
    let Definitions {
        state,
        assignments,
        function_bodies,
        needs_prototype_facts,
        ..
    } = visitor;
    if needs_prototype_facts {
        index_prototype_uncertainty(state, checkpoint)?;
    }
    // All declarations must exist before resolving writes, including hoisted
    // functions and local declarations that shadow an outer binding.
    for (index, write) in assignments.iter().enumerate() {
        if index % WRITE_CHECKPOINT_INTERVAL == 0 {
            checkpoint()?;
        }
        bind_assignment(state, &write.node, write.scope, write.conditionally_skipped);
    }
    for (index, body) in function_bodies.iter().enumerate() {
        if index % WRITE_CHECKPOINT_INTERVAL == 0 {
            checkpoint()?;
        }
        for parameter in &body.parameters {
            let parameter = parameter_pattern(source, *parameter);
            for identifier in write_targets(source, parameter) {
                if identifier.babel_type() == "Identifier" {
                    copy_parameter_to_body(state, &identifier, body.body, body.scope);
                }
            }
        }
    }
    ControlFlow::Continue(())
}

fn is_field<'a>(source: &'a str, parent: &Node<'a>, field: Field, child: &Node<'a>) -> bool {
    parent
        .field(source, field)
        .is_some_and(|value| value.key() == child.key())
}

/// `TSParameterProperty` binds its inner parameter.
fn parameter_pattern<'a>(source: &'a str, parameter: Node<'a>) -> Node<'a> {
    if parameter.babel_type() == "TSParameterProperty" {
        parameter
            .field(source, Field::Parameter)
            .unwrap_or(parameter)
    } else {
        parameter
    }
}

fn push_scope<'a>(state: &mut SemanticState<'a>, scope: ScopeState<'a>) -> ScopeIndex {
    let index = state.scopes.len();
    state.scopes_by_id.set(scope.scope_id.clone(), index);
    state.scopes.push(scope);
    index
}

/// `writeMayBeSkipped`: enclosing control flow can skip this write.
fn write_may_be_skipped<'a>(source: &'a str, node: &Node<'a>, ancestors: &[Node<'a>]) -> bool {
    let mut child = *node;
    for parent in ancestors.iter().rev() {
        if is_function(parent) || matches!(parent.babel_type(), "Program" | "StaticBlock") {
            return false;
        }
        if branch_may_be_skipped(source, parent, &child) {
            return true;
        }
        child = *parent;
    }
    false
}

fn bind_outer_declaration<'a>(state: &mut SemanticState<'a>, node: &Node<'a>, scope: ScopeIndex) {
    let kind = match node.babel_type() {
        "FunctionDeclaration" => DefinitionKind::Function,
        "ClassDeclaration" => DefinitionKind::Class,
        _ => return,
    };
    if let Some(id) = node.field(state.source, Field::Id)
        && let Some(name) = id.identifier_name()
    {
        add_binding(
            state,
            AddBinding {
                scope,
                name,
                kind,
                mutable: false,
                declaration_kind: None,
                definition_node: id,
                initializer: Some(*node),
                direct_origin: None,
                runtime_import: false,
                projection: Vec::new(),
            },
        );
    }
}

fn bind_inner_declaration<'a>(
    state: &mut SemanticState<'a>,
    node: &Node<'a>,
    parent: Option<&Node<'a>>,
    scope: ScopeIndex,
) {
    let source = state.source;
    match node.babel_type() {
        "ImportDeclaration" => bind_imports(state, node, scope),
        "TSImportEqualsDeclaration" => bind_import_equals(state, node, scope),
        "VariableDeclarator" => {
            let declaration = parent.filter(|p| p.babel_type() == "VariableDeclaration");
            let Some(pattern) = node.field(source, Field::Id) else {
                return;
            };
            let target = state.variable_scope(scope, parent);
            bind_pattern(
                state,
                BindPattern {
                    mutable: declaration
                        .is_none_or(|declaration| declaration.declaration_kind() != Some("const")),
                    declaration_kind: declaration
                        .and_then(|declaration| declaration.declaration_kind())
                        .and_then(DeclarationKind::parse),
                    ..BindPattern::new(pattern, node.field(source, Field::Init), target)
                },
            );
        }
        "ClassExpression" => {
            if let Some(id) = node.field(source, Field::Id)
                && let Some(name) = id.identifier_name()
            {
                add_binding(
                    state,
                    AddBinding {
                        scope,
                        name,
                        kind: DefinitionKind::Class,
                        mutable: false,
                        declaration_kind: None,
                        definition_node: id,
                        initializer: Some(*node),
                        direct_origin: None,
                        runtime_import: false,
                        projection: Vec::new(),
                    },
                );
            }
        }
        "CatchClause" => {
            if let Some(param) = node.field(source, Field::Param) {
                bind_pattern(
                    state,
                    BindPattern {
                        mutable: true,
                        kind: DefinitionKind::Catch,
                        ..BindPattern::new(param, None, scope)
                    },
                );
            }
        }
        _ if is_function(node) => {
            for parameter in runtime_function_parameters(source, node) {
                bind_pattern(
                    state,
                    BindPattern {
                        mutable: true,
                        kind: DefinitionKind::Parameter,
                        ..BindPattern::new(parameter_pattern(source, parameter), None, scope)
                    },
                );
            }
        }
        _ => {}
    }
}

fn bind_imports<'a>(state: &mut SemanticState<'a>, node: &Node<'a>, scope: ScopeIndex) {
    let source = state.source;
    let Some(specifier_text) = node
        .field(source, Field::Source)
        .and_then(|literal| literal.string_value_units())
        .map(JsString::from_utf16)
    else {
        return;
    };
    let declaration_runtime = node.import_kind() != Some("type");
    for specifier in node
        .field_list(source, Field::Specifiers)
        .into_iter()
        .flatten()
    {
        let imported_path = match specifier.babel_type() {
            "ImportDefaultSpecifier" => vec![JsString::from("default")],
            "ImportNamespaceSpecifier" => Vec::new(),
            _ => vec![
                specifier
                    .field(source, Field::Imported)
                    .and_then(|imported| static_property_key(source, imported, false))
                    .map_or_else(|| JsString::from("[dynamic]"), |key| key),
            ],
        };
        let Some(local) = specifier.field(source, Field::Local) else {
            continue;
        };
        let Some(name) = local.identifier_name() else {
            continue;
        };
        let runtime_import = declaration_runtime
            && (specifier.babel_type() != "ImportSpecifier"
                || specifier.import_kind() != Some("type"));
        add_binding(
            state,
            AddBinding {
                scope,
                name,
                kind: DefinitionKind::Import,
                mutable: false,
                declaration_kind: None,
                definition_node: local,
                initializer: None,
                direct_origin: Some(ModuleOrigin {
                    resolution_mode: None,
                    specifier: specifier_text.clone(),
                    imported_path,
                }),
                runtime_import,
                projection: Vec::new(),
            },
        );
    }
}

/// `semanticImportEqualsSpecifier` (module-declaration owner).
fn import_equals_specifier(source: &str, node: &Node<'_>) -> Option<JsString> {
    if node.import_kind() == Some("type") {
        return None;
    }
    let reference = node.field(source, Field::ModuleReference)?;
    if reference.babel_type() != "TSExternalModuleReference" {
        return None;
    }
    reference
        .field(source, Field::Expression)
        .filter(|expression| expression.babel_type() == "StringLiteral")
        .and_then(|expression| expression.string_value_units())
        .map(JsString::from_utf16)
}

fn bind_import_equals<'a>(state: &mut SemanticState<'a>, node: &Node<'a>, scope: ScopeIndex) {
    let source = state.source;
    let Some(specifier) = import_equals_specifier(source, node) else {
        return;
    };
    let Some(id) = node.field(source, Field::Id) else {
        return;
    };
    let Some(name) = id.identifier_name() else {
        return;
    };
    add_binding(
        state,
        AddBinding {
            scope,
            name,
            kind: DefinitionKind::Import,
            mutable: false,
            declaration_kind: None,
            definition_node: id,
            initializer: None,
            direct_origin: Some(ModuleOrigin {
                resolution_mode: Some(ResolutionMode::Require),
                specifier,
                imported_path: Vec::new(),
            }),
            runtime_import: false,
            projection: Vec::new(),
        },
    );
}

/// A parameter or catch binding starts with a caller-supplied value that a
/// conditional logical assignment can retain.
fn has_incoming_value(state: &SemanticState<'_>, name: &str, scope: ScopeIndex) -> bool {
    state
        .resolve_from_scope(scope, name)
        .is_some_and(|binding| {
            matches!(
                state.bindings[binding].kind,
                DefinitionKind::Parameter | DefinitionKind::Catch
            )
        })
}

fn bind_assignment<'a>(
    state: &mut SemanticState<'a>,
    node: &Node<'a>,
    scope: ScopeIndex,
    conditionally_skipped: bool,
) {
    let source = state.source;
    match node.babel_type() {
        "AssignmentExpression" => {
            let Some(target) = node.field(source, Field::Left) else {
                return;
            };
            let left = unwrapped(source, target);
            if let Some(name) = left
                .identifier_name()
                .filter(|_| left.babel_type() == "Identifier")
            {
                let exact = match node.operator() {
                    Some("=") => true,
                    Some("||=" | "??=") => !has_incoming_value(state, name, scope),
                    _ => false,
                };
                let initializer = if exact {
                    node.field(source, Field::Right).unwrap_or(*node)
                } else {
                    *node
                };
                add_assignment(
                    state,
                    &left,
                    initializer,
                    scope,
                    conditionally_skipped,
                    Some(*node),
                );
            } else {
                for identifier in write_targets(source, target) {
                    if identifier.babel_type() == "Identifier" {
                        add_assignment(
                            state,
                            &identifier,
                            *node,
                            scope,
                            conditionally_skipped,
                            Some(*node),
                        );
                    }
                }
            }
        }
        "UpdateExpression" => {
            if let Some(argument) = node.field(source, Field::Argument) {
                let argument = unwrapped(source, argument);
                if argument.babel_type() == "Identifier" {
                    add_assignment(state, &argument, *node, scope, conditionally_skipped, None);
                }
            }
        }
        "ForOfStatement" | "ForInStatement" => {
            if iteration_cardinality(source, node, state.prototype_enumeration_may_affect)
                == IterationCardinality::Empty
            {
                return;
            }
            let Some(left) = node.field(source, Field::Left) else {
                return;
            };
            let patterns: Vec<Node<'a>> = if left.babel_type() == "VariableDeclaration" {
                left.field_list(source, Field::Declarations)
                    .into_iter()
                    .flatten()
                    .filter_map(|declarator| declarator.field(source, Field::Id))
                    .collect()
            } else {
                vec![left]
            };
            for pattern in patterns {
                for identifier in write_targets(source, pattern) {
                    if identifier.babel_type() == "Identifier" {
                        add_assignment(
                            state,
                            &identifier,
                            *node,
                            scope,
                            conditionally_skipped,
                            Some(*node),
                        );
                    }
                }
                if node.babel_type() == "ForOfStatement" {
                    // Keep the loop value unknown, but preserve references
                    // yielded into each bound slot.
                    bind_pattern(
                        state,
                        BindPattern {
                            mutable: true,
                            reference_only: true,
                            ..BindPattern::new(pattern, Some(*node), scope)
                        },
                    );
                }
            }
        }
        _ => {}
    }
}

/// `nestedScope`.
fn nested_scope<'a>(
    state: &mut SemanticState<'a>,
    node: &Node<'a>,
    parent: Option<&Node<'a>>,
    parent_scope: ScopeIndex,
) -> Option<ScopeIndex> {
    let source = state.source;
    let switch_owner = parent
        .filter(|parent| {
            node.babel_type() == "SwitchCase" && parent.babel_type() == "SwitchStatement"
        })
        .copied();
    if let Some(owner) = switch_owner {
        let id = scope_id(
            ScopeKind::Block,
            state.context.start(&owner),
            state.context.end(&owner),
        );
        if let Some(&existing) = state.scopes_by_id.get(&id) {
            return Some(existing);
        }
    }
    let kind = scope_kind(source, node, parent)?;
    let owner = switch_owner.unwrap_or(*node);
    let id = scope_id(kind, state.context.start(&owner), state.context.end(&owner));
    let parent_scope_id = match function_name_scope(state, node, parent_scope) {
        Some(name_scope) => state.scopes[name_scope].scope_id.clone(),
        None => state.scopes[parent_scope].scope_id.clone(),
    };
    let scope = ScopeState {
        scope_id: id,
        parent_scope_id: Some(parent_scope_id),
        kind,
        location: state.context.range(&owner),
        bindings_complete: true,
        bindings: InsertionMap::default(),
        dynamic_with_statement: None,
    };
    Some(push_scope(state, scope))
}

/// `functionNameScope`: a named function expression's private name
/// environment, outside its parameters and body.
fn function_name_scope<'a>(
    state: &mut SemanticState<'a>,
    node: &Node<'a>,
    parent_scope: ScopeIndex,
) -> Option<ScopeIndex> {
    if node.babel_type() != "FunctionExpression" {
        return None;
    }
    let id = node.field(state.source, Field::Id)?;
    let name = id.identifier_name()?;
    let scope = ScopeState {
        scope_id: format!(
            "{}:function-name",
            scope_id(
                ScopeKind::Block,
                state.context.start(node),
                state.context.end(node)
            )
        ),
        parent_scope_id: Some(state.scopes[parent_scope].scope_id.clone()),
        kind: ScopeKind::Block,
        location: state.context.range(node),
        bindings_complete: true,
        bindings: InsertionMap::default(),
        dynamic_with_statement: None,
    };
    let index = push_scope(state, scope);
    add_binding(
        state,
        AddBinding {
            scope: index,
            name,
            kind: DefinitionKind::Function,
            mutable: false,
            declaration_kind: None,
            definition_node: id,
            initializer: Some(*node),
            direct_origin: None,
            runtime_import: false,
            projection: Vec::new(),
        },
    );
    Some(index)
}

/// `scopeKind`.
fn scope_kind<'a>(
    source: &'a str,
    node: &Node<'a>,
    parent: Option<&Node<'a>>,
) -> Option<ScopeKind> {
    if is_function(node) {
        return Some(ScopeKind::Function);
    }
    if is_class(node) {
        return Some(ScopeKind::Class);
    }
    match node.babel_type() {
        "CatchClause" => Some(ScopeKind::Catch),
        "ForStatement" | "ForOfStatement" | "ForInStatement" | "SwitchCase" => {
            Some(ScopeKind::Block)
        }
        "StaticBlock" => Some(ScopeKind::StaticBlock),
        "BlockStatement" => match parent {
            Some(parent) if is_function(parent) && is_field(source, parent, Field::Body, node) => {
                // Parameter expressions cannot see body declarations; the
                // body is a separate variable environment only then.
                function_parameters_have_expressions(source, parent).then_some(ScopeKind::Function)
            }
            _ => Some(ScopeKind::Block),
        },
        _ => None,
    }
}

/// `functionParametersHaveExpressions`.
fn function_parameters_have_expressions<'a>(source: &'a str, function: &Node<'a>) -> bool {
    let mut pending = runtime_function_parameters(source, function);
    while let Some(parameter) = pending.pop() {
        match parameter.babel_type() {
            "AssignmentPattern" => return true,
            "TSParameterProperty" => pending.extend(parameter.field(source, Field::Parameter)),
            "RestElement" => pending.extend(parameter.field(source, Field::Argument)),
            "ArrayPattern" => {
                pending.extend(
                    parameter
                        .field_list(source, Field::Elements)
                        .into_iter()
                        .flatten(),
                );
            }
            "ObjectPattern" => {
                for property in parameter
                    .field_list(source, Field::Properties)
                    .into_iter()
                    .flatten()
                {
                    if property.babel_type() == "RestElement" {
                        pending.extend(property.field(source, Field::Argument));
                    } else {
                        if property.computed() {
                            return true;
                        }
                        pending.extend(property.field(source, Field::Value));
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// `BindPatternInput`.
#[derive(Clone)]
struct BindPattern<'a> {
    pattern: Node<'a>,
    initializer: Option<Node<'a>>,
    scope: ScopeIndex,
    mutable: bool,
    declaration_kind: Option<DeclarationKind>,
    kind: DefinitionKind,
    projection: Vec<ProjectionKey>,
    reference_only: bool,
    copy_kind: Option<CopyKind>,
    copy_projection_offset: Option<usize>,
    copy_excluded_keys: Option<Vec<JsString>>,
    copy_start_index: Option<usize>,
    fallback_sources: Option<Vec<Initializer<'a>>>,
    required_sources: Option<Vec<Initializer<'a>>>,
}

impl<'a> BindPattern<'a> {
    fn new(pattern: Node<'a>, initializer: Option<Node<'a>>, scope: ScopeIndex) -> Self {
        Self {
            pattern,
            initializer,
            scope,
            mutable: false,
            declaration_kind: None,
            kind: DefinitionKind::Variable,
            projection: Vec::new(),
            reference_only: false,
            copy_kind: None,
            copy_projection_offset: None,
            copy_excluded_keys: None,
            copy_start_index: None,
            fallback_sources: None,
            required_sources: None,
        }
    }

    fn with_pattern(&self, pattern: Node<'a>) -> Self {
        Self {
            pattern,
            ..self.clone()
        }
    }

    /// `{ node: initializer, projection }` when an initializer exists.
    fn source_entry(&self) -> Option<Initializer<'a>> {
        self.initializer.map(|node| Initializer {
            record_id: 0,
            node,
            projection: self.projection.clone(),
            entry_body: None,
        })
    }
}

fn bind_pattern<'a>(state: &mut SemanticState<'a>, input: BindPattern<'a>) {
    let source = state.source;
    let pattern = input.pattern;
    match pattern.babel_type() {
        "TSParameterProperty" => {
            if let Some(parameter) = pattern.field(source, Field::Parameter) {
                bind_pattern(state, input.with_pattern(parameter));
            }
        }
        "Identifier" => {
            let Some(name) = pattern.identifier_name() else {
                return;
            };
            if input.reference_only {
                if let Some(binding) = state.resolve_from_scope(input.scope, name)
                    && let Some(initializer) = input.initializer
                {
                    state.bindings[binding]
                        .reference_initializers
                        .push(ReferenceInitializer {
                            node: initializer,
                            projection: input.projection,
                            copy_kind: input.copy_kind,
                            copy_projection_offset: input.copy_projection_offset,
                            copy_excluded_keys: input.copy_excluded_keys,
                            copy_start_index: input.copy_start_index,
                            fallback_sources: input.fallback_sources,
                            required_sources: input.required_sources,
                        });
                }
                return;
            }
            add_binding(
                state,
                AddBinding {
                    scope: input.scope,
                    name,
                    kind: input.kind,
                    mutable: input.mutable,
                    declaration_kind: input.declaration_kind,
                    definition_node: pattern,
                    initializer: input.initializer,
                    direct_origin: None,
                    runtime_import: false,
                    projection: input.projection,
                },
            );
        }
        "AssignmentPattern" => {
            let (Some(left), Some(right)) = (
                pattern.field(source, Field::Left),
                pattern.field(source, Field::Right),
            ) else {
                return;
            };
            let incoming = input.source_entry();
            let mut required = input.required_sources.clone().unwrap_or_default();
            required.extend(incoming.clone());
            let first = BindPattern {
                pattern: left,
                initializer: if matches!(
                    input.kind,
                    DefinitionKind::Parameter | DefinitionKind::Catch
                ) {
                    input.initializer
                } else {
                    input.initializer.or(Some(right))
                },
                required_sources: Some(required),
                ..input.clone()
            };
            bind_pattern(state, first);
            let mut fallback = input.fallback_sources.clone().unwrap_or_default();
            fallback.extend(incoming);
            bind_pattern(
                state,
                BindPattern {
                    mutable: input.mutable,
                    kind: input.kind,
                    reference_only: true,
                    fallback_sources: Some(fallback),
                    required_sources: input.required_sources,
                    ..BindPattern::new(left, Some(right), input.scope)
                },
            );
        }
        "RestElement" => {
            if let Some(argument) = pattern.field(source, Field::Argument) {
                bind_pattern(
                    state,
                    BindPattern {
                        initializer: None,
                        mutable: true,
                        ..input.with_pattern(argument)
                    },
                );
            }
        }
        "ObjectPattern" => {
            for property in pattern
                .field_list(source, Field::Properties)
                .into_iter()
                .flatten()
            {
                if property.babel_type() == "RestElement" {
                    let Some(argument) = property.field(source, Field::Argument) else {
                        continue;
                    };
                    bind_pattern(
                        state,
                        BindPattern {
                            initializer: None,
                            mutable: true,
                            projection: Vec::new(),
                            ..input.with_pattern(argument)
                        },
                    );
                    let mut projection = input.projection.clone();
                    projection.push(ProjectionKey::Dynamic);
                    bind_pattern(
                        state,
                        BindPattern {
                            projection,
                            reference_only: true,
                            copy_kind: Some(CopyKind::ObjectRest),
                            copy_projection_offset: Some(input.projection.len()),
                            copy_excluded_keys: Some(
                                object_pattern_keys(source, &pattern).into_iter().collect(),
                            ),
                            ..input.with_pattern(argument)
                        },
                    );
                } else {
                    let key = property
                        .field(source, Field::Key)
                        .and_then(|key| static_property_key(source, key, property.computed()));
                    let Some(value) = property.field(source, Field::Value) else {
                        continue;
                    };
                    let mut projection = input.projection.clone();
                    projection
                        .push(key.map_or(ProjectionKey::Dynamic, |key| ProjectionKey::Name(key)));
                    bind_pattern(
                        state,
                        BindPattern {
                            projection,
                            ..input.with_pattern(value)
                        },
                    );
                }
            }
        }
        "ArrayPattern" => {
            for (index, element) in pattern
                .field_list(source, Field::Elements)
                .into_iter()
                .enumerate()
            {
                let Some(element) = element else { continue };
                let mut projection = input.projection.clone();
                projection.push(ProjectionKey::Index(index));
                bind_pattern(
                    state,
                    BindPattern {
                        projection,
                        ..input.with_pattern(element)
                    },
                );
                if element.babel_type() == "RestElement"
                    && let Some(argument) = element.field(source, Field::Argument)
                {
                    let mut projection = input.projection.clone();
                    projection.push(ProjectionKey::Dynamic);
                    bind_pattern(
                        state,
                        BindPattern {
                            projection,
                            reference_only: true,
                            copy_kind: Some(CopyKind::ArrayRest),
                            copy_projection_offset: Some(input.projection.len()),
                            copy_start_index: Some(index),
                            ..input.with_pattern(argument)
                        },
                    );
                }
            }
        }
        _ => {}
    }
}

/// `AddBindingInput`.
struct AddBinding<'n, 'a> {
    scope: ScopeIndex,
    name: &'n str,
    kind: DefinitionKind,
    mutable: bool,
    declaration_kind: Option<DeclarationKind>,
    definition_node: Node<'a>,
    initializer: Option<Node<'a>>,
    direct_origin: Option<ModuleOrigin>,
    runtime_import: bool,
    projection: Vec<ProjectionKey>,
}

fn add_binding<'a>(state: &mut SemanticState<'a>, input: AddBinding<'_, 'a>) {
    let existing = state.scopes[input.scope].bindings.get(input.name).copied();
    let index = match existing {
        Some(index) => index,
        None => {
            if !state.scopes[input.scope].bindings_complete {
                return;
            }
            let scope_id = state.scopes[input.scope].scope_id.clone();
            let id = binding_id(&scope_id, input.name);
            let index = state.bindings.len();
            state.bindings.push(BindingState {
                binding_id: id.clone(),
                scope_id,
                name: input.name.to_owned(),
                kind: input.kind,
                declaration_kinds: Vec::new(),
                mutable: input.mutable,
                member_writes: Vec::new(),
                escaped_paths: Vec::new(),
                definitions: Vec::new(),
                initializers: Vec::new(),
                reference_initializers: Vec::new(),
                direct_origins: Vec::new(),
                runtime_import: false,
            });
            state.scopes[input.scope]
                .bindings
                .set(input.name.to_owned(), index);
            state.bindings_by_id.set(id, index);
            index
        }
    };
    let location = state.context.range(&input.definition_node);
    let mode = state.static_import_resolution_mode;
    let record_id = input.initializer.map(|_| state.allocate_initializer_id());
    let binding = &mut state.bindings[index];
    binding.mutable |= input.mutable;
    if let Some(kind) = input.declaration_kind
        && !binding.declaration_kinds.contains(&kind)
    {
        binding.declaration_kinds.push(kind);
    }
    binding.definitions.push(Definition {
        kind: input.kind,
        location,
    });
    if let Some(node) = input.initializer {
        binding.initializers.push(Initializer {
            record_id: record_id.expect("initializer identity allocated"),
            node,
            projection: input.projection,
            entry_body: None,
        });
    }
    if let Some(mut origin) = input.direct_origin {
        if origin.resolution_mode.is_none() && mode != ResolutionMode::Import {
            origin.resolution_mode = Some(mode);
        }
        binding.direct_origins.push(origin);
    }
    binding.runtime_import |= input.runtime_import;
}

fn add_assignment<'a>(
    state: &mut SemanticState<'a>,
    identifier: &Node<'a>,
    initializer: Node<'a>,
    scope: ScopeIndex,
    conditionally_skipped: bool,
    write_site: Option<Node<'a>>,
) {
    let Some(name) = identifier.identifier_name() else {
        return;
    };
    let lookup = state.lookup_from_scope(Some(scope), name);
    if lookup == super::state::BindingLookup::Captured {
        return;
    }
    let skipped = conditionally_skipped
        || !matches!(
            lookup,
            super::state::BindingLookup::Binding(_) | super::state::BindingLookup::Ambient
        );
    let site = write_site.unwrap_or(initializer);
    let Some(index) = lookup.binding() else {
        // Unbound identifiers can denote host wrapper bindings (`require`).
        state
            .ambient_binding_writes
            .entry_or(name, Vec::new)
            .push(site);
        return;
    };
    let id = state.bindings[index].binding_id.clone();
    state.binding_writes.entry_or(&id, Vec::new).push(site);
    let location = state.context.range(identifier);
    let record_id = state.allocate_initializer_id();
    let binding = &mut state.bindings[index];
    binding.mutable = true;
    binding.definitions.push(Definition {
        kind: DefinitionKind::Assignment,
        location,
    });
    binding.initializers.push(Initializer {
        record_id,
        node: initializer,
        projection: Vec::new(),
        entry_body: None,
    });
    if skipped {
        state.conditionally_skipped.insert(initializer.key());
    }
}

/// `copyParameterToBody`: a separate body var environment starts with the
/// parameter's value.
fn copy_parameter_to_body<'a>(
    state: &mut SemanticState<'a>,
    identifier: &Node<'a>,
    body: Node<'a>,
    scope: ScopeIndex,
) {
    let Some(name) = identifier.identifier_name() else {
        return;
    };
    let Some(&index) = state.scopes[scope].bindings.get(name) else {
        return;
    };
    {
        let binding = &state.bindings[index];
        if binding.kind != DefinitionKind::Variable
            || binding
                .definitions
                .iter()
                .any(|definition| definition.kind == DefinitionKind::Function)
        {
            return;
        }
    }
    let record_id = state.allocate_initializer_id();
    state.bindings[index].initializers.insert(
        0,
        Initializer {
            record_id,
            node: *identifier,
            projection: Vec::new(),
            entry_body: Some(body),
        },
    );
    let mut position = state.bindings[index].initializers.len();
    while position > 0 {
        position -= 1;
        let initializer = &state.bindings[index].initializers[position];
        let self_initialization = initializer.entry_body.is_none()
            && initializer.projection.is_empty()
            && initializer.node.babel_type() == "Identifier"
            && initializer
                .node
                .identifier_name()
                .is_some_and(|own| state.resolve_binding(&initializer.node, own) == Some(index));
        if self_initialization {
            // Direct self-initialization preserves the prior value.
            state.bindings[index].initializers.remove(position);
        }
    }
}

/// Built-in prototype owners whose mutation or exposure the pass tracks.
const PROTOTYPE_OWNERS: [&str; 3] = ["Object", "Array", "String"];
const PROTOTYPE_MUTATORS: [&str; 3] = ["defineProperty", "defineProperties", "setPrototypeOf"];

/// `indexPrototypeUncertaintySteps`: preserve uncertainty when source can
/// change or expose a built-in prototype.
fn index_prototype_uncertainty<'a, B>(
    state: &mut SemanticState<'a>,
    checkpoint: &mut impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B> {
    struct Prototype<'s, 'a> {
        state: &'s mut SemanticState<'a>,
    }
    impl<'a> Prototype<'_, 'a> {
        fn taint(&mut self, owner: &str) {
            if owner == "Object" {
                self.state.prototype_require_mutation_observed = None;
            }
            self.state.prototype_enumeration_may_affect = None;
        }

        fn global_owner(&self, node: Node<'a>) -> Option<&'static str> {
            let value = unwrapped(self.state.source, node);
            PROTOTYPE_OWNERS.into_iter().find(|owner| {
                is_unmodified_global_reference(self.state, &value, owner)
                    || (is_identifier_named(&value, owner)
                        && self.state.resolve_binding(&value, owner).is_none())
            })
        }

        fn prototype_owner(&self, node: Node<'a>) -> Option<&'static str> {
            let source = self.state.source;
            let value = unwrapped(source, node);
            if !is_member(&value) {
                return None;
            }
            let key = value
                .field(source, Field::Property)
                .and_then(|property| static_property_key(source, property, value.computed()));
            if key.as_ref().is_none_or(|key| key != "prototype") {
                return None;
            }
            value
                .field(source, Field::Object)
                .and_then(|object| self.global_owner(object))
        }

        fn object_method(&self, node: Node<'a>) -> Option<String> {
            let source = self.state.source;
            let callee = unwrapped(source, node);
            if !is_member(&callee)
                || callee
                    .field(source, Field::Object)
                    .and_then(|object| self.global_owner(object))
                    != Some("Object")
            {
                return None;
            }
            callee
                .field(source, Field::Property)
                .and_then(|property| static_property_key(source, property, callee.computed()))
                .and_then(|key| key.try_to_string().ok())
        }

        fn owner_of(&self, node: Node<'a>) -> Option<&'static str> {
            self.prototype_owner(node)
                .or_else(|| self.global_owner(node))
        }
    }
    impl<'a> AstVisitor<'a> for Prototype<'_, 'a> {
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _: &[Node<'a>]) {
            let source = self.state.source;
            if let Some(write) = write_site_target(source, node) {
                for target in write_targets(source, write) {
                    let value = unwrapped(source, target);
                    let owner = if is_member(&value) {
                        value
                            .field(source, Field::Object)
                            .and_then(|object| self.owner_of(object))
                    } else {
                        self.global_owner(value)
                    };
                    if let Some(owner) = owner {
                        self.taint(owner);
                    }
                }
            }
            if is_call(node)
                && let Some(callee_field) = node.field(source, Field::Callee)
            {
                let method = self.object_method(callee_field);
                let callee = unwrapped(source, callee_field);
                if is_member(&callee)
                    && let Some(owner) = callee
                        .field(source, Field::Object)
                        .and_then(|object| self.prototype_owner(object))
                {
                    self.taint(owner);
                }
                for (index, argument) in node
                    .field_list(source, Field::Arguments)
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    let Some(owner) = self.owner_of(argument) else {
                        continue;
                    };
                    // These intrinsics mutate only their first argument.
                    if method
                        .as_deref()
                        .is_some_and(|method| PROTOTYPE_MUTATORS.contains(&method))
                        && index != 0
                    {
                        continue;
                    }
                    self.taint(owner);
                }
            }
            let Some(owner) = self.owner_of(*node) else {
                return;
            };
            let Some(parent) = parent else { return };
            if is_member(parent) && is_field(source, parent, Field::Object, node) {
                return;
            }
            if is_call(parent)
                && parent
                    .field_list(source, Field::Arguments)
                    .into_iter()
                    .flatten()
                    .any(|argument| argument.key() == node.key())
            {
                return;
            }
            if node.babel_type() == "Identifier" && reference_role(source, node, parent).is_none() {
                return;
            }
            self.taint(owner);
        }
    }
    let root = state.program;
    let source = state.source;
    let mut visitor = Prototype { state };
    traverse(root, source, &mut visitor, &mut *checkpoint)
}
