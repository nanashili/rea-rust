//! Literal CommonJS origins recovered through a structurally proven Webpack
//! bootstrap.  This is intentionally a consumer of the static-analysis
//! bootstrap and integrity producers; it does not execute bundle code.

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

use crate::javascript::ast::{AstVisitor, Field, Node, NodeKey, traverse};
use crate::javascript::static_analysis::babel::function_flags;
use crate::javascript::static_analysis::bootstrap::javascript_bootstrap_at;
use crate::javascript::static_analysis::bootstrap_integrity::prove_javascript_bootstrap_integrity;
use crate::javascript::static_analysis::helpers::{
    argument_value, module_factory, module_property_name,
};

use super::ast_values::{static_property_key, unwrapped};
use super::identity_writes::{IdentityWriteKind, collect_identity_writes_steps};
use super::module_interop::StateFacts;
use super::module_interop::{create_module_interop, is_fresh_object, static_string};
use super::require_origin::{RequireOrigin, member_chain, ordinary_require_origin};
use super::state::{DefinitionKind, SemanticState};
use super::value_types::JsString;

#[derive(Clone, Debug)]
pub(crate) struct BootstrapExternals<'a> {
    loader_binding_ids: HashSet<String>,
    interop_getter_binding_ids: HashSet<String>,
    externals: HashMap<String, Option<JsString>>,
    _marker: std::marker::PhantomData<Node<'a>>,
}

/// Per-analysis proof memo matching the TypeScript state's WeakMap cache.
pub(crate) struct BundledRequireProofCache<'a> {
    proofs: HashMap<NodeKey, Option<BootstrapExternals<'a>>>,
}

impl<'a> Default for BundledRequireProofCache<'a> {
    fn default() -> Self {
        Self {
            proofs: HashMap::new(),
        }
    }
}

/// Recover a literal require reached through a proven Webpack bootstrap.
pub fn bundled_require_origin<'a>(
    state: &SemanticState<'a>,
    node: Option<Node<'a>>,
) -> Option<RequireOrigin<'a>> {
    let chain = member_chain(state.source, node)?;
    let current = chain.root;
    let arguments = current.field_list(state.source, Field::Arguments);

    // Webpack's n.n(module) is accepted only when n is the same proven loader
    // and its canonical default-export getter is installed before dispatch.
    if chain.members.is_empty()
        && current.babel_type() == "CallExpression"
        && arguments.len() == 1
        && current
            .field(state.source, Field::Callee)
            .is_some_and(|callee| {
                callee.babel_type() == "MemberExpression"
                    && callee
                        .field(state.source, Field::Property)
                        .and_then(|property| {
                            static_property_key(state.source, property, callee.computed())
                        })
                        .is_some_and(|property| property == "n")
            })
    {
        let callee = current.field(state.source, Field::Callee)?;
        let loader = unwrapped(state.source, callee.field(state.source, Field::Object)?);
        let argument = arguments.first().copied().flatten();
        let nested = bundled_require_origin(state, argument)?;
        let loader_id = state
            .resolve_binding(&loader, loader.identifier_name()?)
            .map(|index| state.binding(index).binding_id.clone())?;
        let nested_callee = nested.call.field(state.source, Field::Callee)?;
        let nested_id = state
            .resolve_binding(&nested_callee, nested_callee.identifier_name()?)
            .map(|index| state.binding(index).binding_id.clone())?;
        let proof = bootstrap_proof_for_loader_call(state, nested.call, &loader_id)?;
        if nested.origin.imported_path.is_empty()
            && loader_id == nested_id
            && proof.loader_binding_ids.contains(&loader_id)
            && proof.interop_getter_binding_ids.contains(&loader_id)
        {
            return Some(nested);
        }
    }

    if current.babel_type() != "CallExpression" {
        return None;
    }
    if arguments.len() != 1 {
        return None;
    }
    let callee = unwrapped(state.source, current.field(state.source, Field::Callee)?);
    let name = callee.identifier_name()?;
    let key = argument_value(
        state.source,
        current
            .field_list(state.source, Field::Arguments)
            .first()
            .copied()
            .flatten(),
    )?;
    if state.resolution_blocked(&callee, name) {
        return None;
    }
    let binding = state.resolve_binding(&callee, name)?;
    let binding_state = state.binding(binding);
    if binding_state.definitions.len() != 1
        || binding_state.definitions[0].kind == DefinitionKind::Assignment
    {
        return None;
    }
    let mut ancestor = state.parent_of(&current);
    while let Some(candidate) = ancestor {
        if candidate.babel_type() == "CallExpression" {
            if let Some(proof) = bootstrap_externals(state, candidate) {
                if proof.loader_binding_ids.contains(&binding_state.binding_id) {
                    return proof.externals.get(key.as_ref()).and_then(|specifier| {
                        specifier.as_ref().map(|specifier| RequireOrigin {
                            origin: super::state::ModuleOrigin {
                                specifier: specifier.clone(),
                                imported_path: chain.members.clone(),
                                resolution_mode: Some(super::state::ResolutionMode::Require),
                            },
                            call: current,
                        })
                    });
                }
            }
        }
        ancestor = state.parent_of(&candidate);
    }
    None
}

fn bootstrap_proof_for_loader_call<'a>(
    state: &SemanticState<'a>,
    call: Node<'a>,
    loader_id: &str,
) -> Option<BootstrapExternals<'a>> {
    let mut ancestor = state.parent_of(&call);
    while let Some(candidate) = ancestor {
        if candidate.babel_type() == "CallExpression" {
            if let Some(proof) = bootstrap_externals(state, candidate) {
                if proof.loader_binding_ids.contains(loader_id) {
                    return Some(proof);
                }
            }
        }
        ancestor = state.parent_of(&candidate);
    }
    None
}

fn bootstrap_externals<'a>(
    state: &SemanticState<'a>,
    call: Node<'a>,
) -> Option<BootstrapExternals<'a>> {
    let key = call.key();
    if let Some(cached) = state.bundled_require_proofs.borrow().proofs.get(&key) {
        return cached.clone();
    }

    let proof = prove_bootstrap_externals(state, call);
    state
        .bundled_require_proofs
        .borrow_mut()
        .proofs
        .insert(key, proof.clone());
    proof
}

fn prove_bootstrap_externals<'a>(
    state: &SemanticState<'a>,
    call: Node<'a>,
) -> Option<BootstrapExternals<'a>> {
    let facts = StateFacts::new(state);
    let bootstrap = javascript_bootstrap_at(&state.context, &call, &facts)?;
    let loader = state
        .bindings_by_id
        .get(&bootstrap.loader_binding_id)
        .copied()?;
    if state.binding(loader).definitions.len() != 1
        || state.binding(loader).definitions[0].kind != DefinitionKind::Function
    {
        return None;
    }
    let mut loader_ids = HashSet::from([bootstrap.loader_binding_id.clone()]);
    let properties = bootstrap.table.field_list(state.source, Field::Properties);
    for property in properties.iter().flatten() {
        let factory = module_factory(&state.context, property)?;
        let parameter = factory
            .field_list(state.source, Field::Params)
            .get(2)
            .copied()
            .flatten();
        if let Some(parameter) = parameter.filter(|node| node.identifier_name().is_some()) {
            if let Some(index) = state.resolve_binding(&parameter, parameter.identifier_name()?) {
                if state.binding(index).definitions.len() == 1
                    && state.binding(index).definitions[0].kind == DefinitionKind::Parameter
                {
                    loader_ids.insert(state.binding(index).binding_id.clone());
                }
            }
        }
    }
    let integrity = prove_javascript_bootstrap_integrity(
        &state.context,
        &call,
        &bootstrap,
        &loader_ids,
        &facts,
    )?;
    let mut externals = HashMap::new();
    for property in properties.iter().flatten() {
        let key = module_property_name(&state.context, property);
        let factory = module_factory(&state.context, property)?;
        let value = if integrity.replaced_keys.contains(&key) {
            None
        } else {
            external_specifier(state, factory)
        };
        externals
            .entry(key)
            .and_modify(|entry: &mut Option<JsString>| *entry = None)
            .or_insert(value);
    }
    Some(BootstrapExternals {
        interop_getter_binding_ids: canonical_interop_bindings(state, &bootstrap, &loader_ids),
        loader_binding_ids: loader_ids,
        externals,
        _marker: std::marker::PhantomData,
    })
}

fn external_specifier<'a>(state: &SemanticState<'a>, factory: Node<'a>) -> Option<JsString> {
    let parameters = factory.field_list(state.source, Field::Params);
    let module_parameter = parameters.first().copied().flatten()?;
    if module_parameter.identifier_name().is_none()
        || parameters
            .iter()
            .flatten()
            .filter_map(Node::identifier_name)
            .collect::<HashSet<_>>()
            .len()
            != parameters.iter().flatten().count()
        || function_flags(&factory).is_some_and(|(async_, generator)| async_ || generator)
        || (factory.babel_type() == "ObjectMethod" && factory.declaration_kind() != Some("method"))
    {
        return None;
    }
    let expression = if let Some(body) = factory.field(state.source, Field::Body) {
        if body.babel_type() == "BlockStatement" {
            let statements = body.field_list(state.source, Field::Body);
            if statements.len() != 1 {
                return None;
            }
            let statement = statements.first().copied().flatten()?;
            if statement.babel_type() != "ExpressionStatement" {
                return None;
            }
            statement.field(state.source, Field::Expression)?
        } else {
            body
        }
    } else {
        return None;
    };
    if expression.babel_type() != "AssignmentExpression" || expression.operator() != Some("=") {
        return None;
    }
    let left = expression.field(state.source, Field::Left)?;
    if left.babel_type() != "MemberExpression"
        || static_property_key(
            state.source,
            left.field(state.source, Field::Property)?,
            left.computed(),
        )? != JsString::from("exports")
    {
        return None;
    }
    let module_binding =
        state.resolve_binding(&module_parameter, module_parameter.identifier_name()?)?;
    let target = unwrapped(state.source, left.field(state.source, Field::Object)?);
    let target_binding = state.resolve_binding(&target, target.identifier_name()?)?;
    if module_binding != target_binding {
        return None;
    }
    let required = ordinary_require_origin(state, expression.field(state.source, Field::Right))?;
    (required.origin.imported_path.is_empty()).then_some(required.origin.specifier)
}

fn canonical_interop_bindings<'a>(
    state: &SemanticState<'a>,
    bootstrap: &crate::javascript::static_analysis::bootstrap::Bootstrap<'a>,
    loader_ids: &HashSet<String>,
) -> HashSet<String> {
    let mut writes = Vec::new();
    let mut interop = create_module_interop(state);
    let _ = collect_identity_writes_steps(
        state.program,
        state.source,
        |root, kind, _site| {
            if kind != IdentityWriteKind::Member {
                return Vec::new();
            }
            let root = unwrapped(state.source, root);
            let Some(name) = root.identifier_name() else {
                return Vec::new();
            };
            let Some(index) = state.resolve_binding(&root, name) else {
                return Vec::new();
            };
            if loader_ids.contains(&state.binding(index).binding_id) {
                vec![vec![Some(JsString::from("loader"))]]
            } else {
                Vec::new()
            }
        },
        |node| interop.intrinsic_invocation(node),
        |node| static_string(state, node),
        |node| is_fresh_object(state, node),
        |node, path| {
            if path.len() < 2
                || path
                    .get(1)
                    .is_some_and(|value| value.as_ref().is_some_and(|value| value == "n"))
                || path.get(1).is_some_and(Option::is_none)
            {
                writes.push(node);
            }
        },
        |_node, _invocation| {},
    );
    if writes.len() != 1 {
        return HashSet::new();
    }
    let write = writes[0];
    if !is_canonical_getter(state, write)
        || !is_installed_before_entry_dispatch(state, bootstrap.body, loader_ids, write)
    {
        return HashSet::new();
    }
    loader_ids.clone()
}

fn is_installed_before_entry_dispatch<'a>(
    state: &SemanticState<'a>,
    body: Node<'a>,
    loader_ids: &HashSet<String>,
    write: Node<'a>,
) -> bool {
    let Some(statement) = state.parent_of(&write) else {
        return false;
    };
    if statement.babel_type() != "ExpressionStatement" {
        return false;
    }
    let statements = body.field_list(state.source, Field::Body);
    let Some(write_index) = statements.iter().position(|candidate| {
        candidate.is_some_and(|candidate| {
            state.context.start(&candidate) == state.context.start(&statement)
        })
    }) else {
        return false;
    };
    let mut entry_index = None;
    for (index, statement) in statements.iter().enumerate() {
        let Some(statement) = statement else {
            continue;
        };
        let mut visitor = EntryDispatchVisitor {
            state,
            loader_ids,
            found: false,
        };
        let _ = traverse(*statement, state.source, &mut visitor, || {
            ControlFlow::<()>::Continue(())
        });
        if visitor.found {
            entry_index = Some(index);
            break;
        }
    }
    entry_index.is_some_and(|index| index > write_index)
}

struct EntryDispatchVisitor<'a, 's> {
    state: &'s SemanticState<'a>,
    loader_ids: &'s HashSet<String>,
    found: bool,
}

impl<'a> AstVisitor<'a> for EntryDispatchVisitor<'a, '_> {
    fn enter(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
        if self.found || node.babel_type() != "CallExpression" || ancestors.iter().any(is_function)
        {
            return;
        }
        let Some(callee) = node.field(self.state.source, Field::Callee) else {
            return;
        };
        let Some(name) = callee.identifier_name() else {
            return;
        };
        let Some(index) = self.state.resolve_binding(&callee, name) else {
            return;
        };
        self.found = self
            .loader_ids
            .contains(&self.state.binding(index).binding_id);
    }
}

fn is_function(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "FunctionDeclaration"
            | "FunctionExpression"
            | "ArrowFunctionExpression"
            | "ObjectMethod"
            | "ClassMethod"
    )
}

fn is_canonical_getter<'a>(state: &SemanticState<'a>, write: Node<'a>) -> bool {
    let Some(right) = write.field(state.source, Field::Right) else {
        return false;
    };
    if right.babel_type() != "ArrowFunctionExpression" {
        return false;
    }
    let parameters = right.field_list(state.source, Field::Params);
    if parameters.len() != 1 {
        return false;
    }
    let Some(parameter) = parameters.first().copied().flatten() else {
        return false;
    };
    let Some(name) = parameter.identifier_name() else {
        return false;
    };
    let Some(index) = state.resolve_binding(&parameter, name) else {
        return false;
    };
    let binding_id = state.binding(index).binding_id.clone();
    let Some(body) = right.field(state.source, Field::Body) else {
        return false;
    };
    if body.babel_type() != "ConditionalExpression" {
        return false;
    }
    let Some(test) = body.field(state.source, Field::Test) else {
        return false;
    };
    if test.babel_type() != "LogicalExpression" || test.operator() != Some("&&") {
        return false;
    }
    let Some(test_left) = test.field(state.source, Field::Left) else {
        return false;
    };
    let Some(test_right) = test.field(state.source, Field::Right) else {
        return false;
    };
    if !same_binding(state, test_left, &binding_id) {
        return false;
    }
    if test_right.babel_type() != "MemberExpression" {
        return false;
    }
    if !test_right
        .field(state.source, Field::Object)
        .is_some_and(|object| same_binding(state, object, &binding_id))
    {
        return false;
    }
    if !test_right
        .field(state.source, Field::Property)
        .and_then(|property| static_property_key(state.source, property, test_right.computed()))
        .is_some_and(|property| property == "__esModule")
    {
        return false;
    }
    let Some(consequent) = body.field(state.source, Field::Consequent) else {
        return false;
    };
    let Some(alternate) = body.field(state.source, Field::Alternate) else {
        return false;
    };
    let default_getter = consequent.babel_type() == "ArrowFunctionExpression"
        && consequent
            .field_list(state.source, Field::Params)
            .is_empty()
        && consequent
            .field(state.source, Field::Body)
            .is_some_and(|value| {
                value.babel_type() == "MemberExpression"
                    && value
                        .field(state.source, Field::Object)
                        .is_some_and(|object| same_binding(state, object, &binding_id))
                    && value
                        .field(state.source, Field::Property)
                        .and_then(|property| {
                            static_property_key(state.source, property, value.computed())
                        })
                        .is_some_and(|property| property == "default")
            });
    let module_getter = alternate.babel_type() == "ArrowFunctionExpression"
        && alternate.field_list(state.source, Field::Params).is_empty()
        && alternate
            .field(state.source, Field::Body)
            .is_some_and(|value| same_binding(state, value, &binding_id));
    default_getter && module_getter
}

fn same_binding<'a>(state: &SemanticState<'a>, node: Node<'a>, binding_id: &str) -> bool {
    node.identifier_name()
        .and_then(|name| state.resolve_binding(&node, name))
        .is_some_and(|index| state.binding(index).binding_id == binding_id)
}
