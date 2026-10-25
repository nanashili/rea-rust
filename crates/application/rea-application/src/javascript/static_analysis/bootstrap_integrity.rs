//! Port of `javascriptBootstrapIntegrity.ts`: prove that `loader(key)`
//! returns the exports of the factory declared at `table[key]`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::ControlFlow;

use super::babel::{function_flags, is_field, is_referenced, same};
use super::bootstrap::Bootstrap;
use super::helpers::argument_value;
use super::semantics::StaticSemantics;
use crate::javascript::ast::{AstContext, AstVisitor, Field, Node, NodeSet, traverse};
use crate::javascript::semantic::ast_values::{is_function, static_property_key};

/// Slots a visible literal write may have replaced; the rest stay as
/// declared (`JavaScriptBootstrapIntegrity`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapIntegrity {
    pub replaced_keys: BTreeSet<String>,
}

struct LoaderShape<'a> {
    parameter_id: String,
    /// The single unconditional `table[key](...)` call.
    dispatch: Node<'a>,
    dispatches: NodeSet,
    module_id: String,
    cache_id: Option<String>,
    /// Cache reads, cache writes and deletes the loader itself performs.
    cache_sites: NodeSet,
}

struct Ctx<'s, 'a> {
    cx: &'s AstContext<'a>,
    semantics: &'s dyn StaticSemantics<'a>,
}

impl<'a> Ctx<'_, 'a> {
    fn source(&self) -> &'a str {
        self.cx.source()
    }
    fn binding_of(&self, node: &Node<'a>) -> Option<&str> {
        self.semantics.binding_id(node)
    }
    fn key(&self, owner: &Node<'a>, field: Field) -> Option<String> {
        owner
            .field(self.source(), field)
            .and_then(|property| static_property_key(self.source(), property, owner.computed()))
            .and_then(|key| key.try_to_string().ok())
    }
    fn is_member(&self, node: Option<&Node<'a>>) -> bool {
        node.is_some_and(|it| it.babel_type() == "MemberExpression")
    }
    fn identifier(&self, node: Option<Node<'a>>) -> Option<Node<'a>> {
        node.filter(|it| it.babel_type() == "Identifier")
    }
}

fn is_assign(node: Option<&Node<'_>>, operator: Option<&str>) -> bool {
    node.is_some_and(|it| {
        it.babel_type() == "AssignmentExpression"
            && operator.is_none_or(|op| it.operator() == Some(op))
    })
}

fn is_delete(node: Option<&Node<'_>>) -> bool {
    node.is_some_and(|it| it.babel_type() == "UnaryExpression" && it.operator() == Some("delete"))
}

fn is_update(node: Option<&Node<'_>>) -> bool {
    node.is_some_and(|it| it.babel_type() == "UpdateExpression")
}

/// `proveJavaScriptBootstrapIntegrity`. `None` when any part is unproven.
pub fn prove_javascript_bootstrap_integrity<'a>(
    cx: &AstContext<'a>,
    call: &Node<'a>,
    bootstrap: &Bootstrap<'a>,
    loader_ids: &HashSet<String>,
    semantics: &dyn StaticSemantics<'a>,
) -> Option<BootstrapIntegrity> {
    let c = Ctx { cx, semantics };
    let source = cx.source();
    for property in bootstrap
        .table
        .field_list(source, Field::Properties)
        .into_iter()
        .flatten()
    {
        if property.babel_type() == "SpreadElement" || c.key(&property, Field::Key).is_none() {
            return None;
        }
    }
    let loader = bootstrap
        .body
        .field_list(source, Field::Body)
        .into_iter()
        .flatten()
        .find(|statement| {
            statement.babel_type() == "FunctionDeclaration"
                && statement.field(source, Field::Id).is_some_and(|id| {
                    c.binding_of(&id) == Some(bootstrap.loader_binding_id.as_str())
                })
        })?;
    let shape = loader_shape(&c, &loader, &bootstrap.table_binding_id)?;
    references_are_contained(&c, call, bootstrap, &shape, loader_ids)
}

fn loader_shape<'a>(c: &Ctx<'_, 'a>, loader: &Node<'a>, table_id: &str) -> Option<LoaderShape<'a>> {
    let source = c.source();
    let parameter = loader
        .field_list(source, Field::Params)
        .first()
        .copied()
        .flatten();
    let parameter_id = c
        .identifier(parameter)
        .and_then(|parameter| c.binding_of(&parameter))?
        .to_owned();
    // A rewritten key would dispatch a different slot than the caller named.
    let (is_async, generator) = function_flags(loader).unwrap_or((false, false));
    if c.semantics
        .binding_by_id(&parameter_id)
        .map(|it| it.definitions)
        != Some(1)
        || is_async
        || generator
    {
        return None;
    }
    let body = loader.field(source, Field::Body)?;
    struct Scan<'s, 'c, 'a> {
        c: &'s Ctx<'c, 'a>,
        table_id: &'s str,
        parameter_id: &'s str,
        dispatches: NodeSet,
        calls: Vec<Node<'a>>,
        modules: Vec<String>,
        returns: Vec<Option<Node<'a>>>,
    }
    impl<'a> AstVisitor<'a> for Scan<'_, '_, 'a> {
        fn skip(&mut self, node: &Node<'a>) -> bool {
            is_function(node)
        }
        fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, _: &[Node<'a>]) {
            if node.babel_type() == "ReturnStatement" {
                self.returns
                    .push(node.field(self.c.source(), Field::Argument));
            }
            if node.babel_type() != "CallExpression" {
                return;
            }
            let Some((table, module_id)) =
                table_dispatch(self.c, node, self.table_id, self.parameter_id)
            else {
                return;
            };
            self.dispatches.insert(table.key());
            self.calls.push(*node);
            if let Some(module_id) = module_id
                && !self.modules.contains(&module_id)
            {
                self.modules.push(module_id);
            }
        }
    }
    let mut scan = Scan {
        c,
        table_id,
        parameter_id: &parameter_id,
        dispatches: NodeSet::default(),
        calls: Vec::new(),
        modules: Vec::new(),
        returns: Vec::new(),
    };
    let _: ControlFlow<()> = traverse(body, source, &mut scan, || ControlFlow::Continue(()));
    if scan.calls.len() != 1 || scan.modules.len() != 1 {
        return None;
    }
    let Scan {
        dispatches,
        calls,
        modules,
        returns,
        ..
    } = scan;
    let dispatch = calls[0];
    let module_id = modules[0].clone();
    if !runs_unconditionally(c, &dispatch, &body) {
        return None;
    }
    let cache = match module_cache(c, &module_id, &parameter_id) {
        Cache::Unproven => return None,
        Cache::None => None,
        Cache::Slot { cache_id, site } => Some((cache_id, site)),
    };
    if !module_object_contained(c, &body, &module_id, &dispatch) {
        return None;
    }
    let mut cache_sites = NodeSet::default();
    if let Some((_, site)) = &cache {
        cache_sites.insert(site.key());
    }
    let shape = LoaderShape {
        parameter_id,
        dispatch,
        dispatches,
        module_id,
        cache_id: cache.map(|(cache_id, _)| cache_id),
        cache_sites,
    };
    if returns
        .iter()
        .all(|argument| returns_module_exports(c, *argument, &shape))
    {
        with_cache_reads(c, &body, shape)
    } else {
        None
    }
}

/// `table[key](module, ...)` or `table[key].call(thisArg, module, ...)`:
/// the table identifier and the module binding, when an identifier.
fn table_dispatch<'a>(
    c: &Ctx<'_, 'a>,
    call: &Node<'a>,
    table_id: &str,
    parameter_id: &str,
) -> Option<(Node<'a>, Option<String>)> {
    let source = c.source();
    let callee = call.field(source, Field::Callee)?;
    let via_call = c.is_member(Some(&callee))
        && c.key(&callee, Field::Property)
            .is_some_and(|key| key == "call");
    let slot = if via_call {
        callee.field(source, Field::Object)?
    } else {
        callee
    };
    if !c.is_member(Some(&slot)) || !slot.computed() {
        return None;
    }
    let object = c.identifier(slot.field(source, Field::Object))?;
    let property = c.identifier(slot.field(source, Field::Property))?;
    if c.binding_of(&object) != Some(table_id) || c.binding_of(&property) != Some(parameter_id) {
        return None;
    }
    let module = call
        .field_list(source, Field::Arguments)
        .get(usize::from(via_call))
        .copied()
        .flatten();
    let module_id = c
        .identifier(module)
        .and_then(|module| c.binding_of(&module))
        .map(str::to_owned);
    Some((object, module_id))
}

enum Cache<'a> {
    /// The module binding is not proven.
    Unproven,
    /// The module object is a fresh literal without a cache.
    None,
    Slot {
        cache_id: String,
        site: Node<'a>,
    },
}

/// `moduleCache`: the module object is a fresh literal, optionally stored as
/// `cache[key]`.
fn module_cache<'a>(c: &Ctx<'_, 'a>, module_id: &str, parameter_id: &str) -> Cache<'a> {
    let source = c.source();
    let definitions = c
        .semantics
        .binding_by_id(module_id)
        .map(|it| it.definitions);
    let Some(initializer) = c.semantics.stable_initializer(module_id) else {
        return Cache::Unproven;
    };
    if definitions != Some(1) || initializer.projection_len != 0 {
        return Cache::Unproven;
    }
    let value = initializer.node;
    if is_plain_object(c, &value) {
        return Cache::None;
    }
    if !is_assign(Some(&value), Some("="))
        || !value
            .field(source, Field::Right)
            .is_some_and(|right| is_plain_object(c, &right))
    {
        return Cache::Unproven;
    }
    let Some(left) = value.field(source, Field::Left) else {
        return Cache::Unproven;
    };
    match keyed_slot(c, &left, parameter_id) {
        Some(cache_id) if starts_empty(c, &cache_id) => Cache::Slot {
            cache_id,
            site: left,
        },
        _ => Cache::Unproven,
    }
}

/// A pre-populated cache could answer the early return without a dispatch.
fn starts_empty(c: &Ctx<'_, '_>, cache_id: &str) -> bool {
    let definitions = c.semantics.binding_by_id(cache_id).map(|it| it.definitions);
    let Some(initializer) = c.semantics.stable_initializer(cache_id) else {
        return false;
    };
    definitions == Some(1)
        && initializer.projection_len == 0
        && initializer.node.babel_type() == "ObjectExpression"
        && initializer
            .node
            .field_list(c.source(), Field::Properties)
            .is_empty()
}

/// An object literal of ordinary data properties.
fn is_plain_object<'a>(c: &Ctx<'_, 'a>, node: &Node<'a>) -> bool {
    node.babel_type() == "ObjectExpression"
        && node
            .field_list(c.source(), Field::Properties)
            .into_iter()
            .flatten()
            .all(|property| {
                property.babel_type() == "ObjectProperty"
                    && !property.computed()
                    && property
                        .field(c.source(), Field::Key)
                        .and_then(|key| static_property_key(c.source(), key, false))
                        .is_none_or(|key| key != "__proto__")
            })
}

/// Every ancestor up to the loader body executes whenever the loader runs.
fn runs_unconditionally<'a>(c: &Ctx<'_, 'a>, dispatch: &Node<'a>, body: &Node<'a>) -> bool {
    let source = c.source();
    let mut child = *dispatch;
    let mut parent = c.semantics.parent(&child);
    while let Some(current) = parent {
        if same(&child, body) {
            break;
        }
        let ordered = match current.babel_type() {
            "SequenceExpression" | "ExpressionStatement" | "ReturnStatement" | "BlockStatement" => {
                true
            }
            "MemberExpression" => is_field(source, &current, Field::Object, &child),
            "CallExpression" => is_field(source, &current, Field::Callee, &child),
            "TryStatement" => is_field(source, &current, Field::Block, &child),
            _ => false,
        };
        if !ordered {
            return false;
        }
        child = current;
        parent = c.semantics.parent(&current);
    }
    same(&child, body)
}

/// The module object reaches only the dispatch, `.exports` reads after it,
/// and writes to members other than `exports`.
fn module_object_contained<'a>(
    c: &Ctx<'_, 'a>,
    body: &Node<'a>,
    module_id: &str,
    dispatch: &Node<'a>,
) -> bool {
    struct Scan<'s, 'c, 'a> {
        c: &'s Ctx<'c, 'a>,
        module_id: &'s str,
        dispatch: &'s Node<'a>,
        contained: bool,
    }
    impl<'a> AstVisitor<'a> for Scan<'_, '_, 'a> {
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
            let Some(parent) = parent else { return };
            if !self.contained || node.babel_type() != "Identifier" {
                return;
            }
            let grandparent = ancestors
                .len()
                .checked_sub(2)
                .map(|index| &ancestors[index]);
            if !is_referenced(self.c.source(), node, parent, grandparent)
                || self.c.binding_of(node) != Some(self.module_id)
            {
                return;
            }
            self.contained = !ancestors.iter().any(is_function)
                && module_use(self.c, node, parent, grandparent, self.dispatch);
        }
    }
    let mut scan = Scan {
        c,
        module_id,
        dispatch,
        contained: true,
    };
    let _: ControlFlow<()> = traverse(*body, c.source(), &mut scan, || ControlFlow::Continue(()));
    scan.contained
}

fn module_use<'a>(
    c: &Ctx<'_, 'a>,
    node: &Node<'a>,
    parent: &Node<'a>,
    grandparent: Option<&Node<'a>>,
    dispatch: &Node<'a>,
) -> bool {
    let source = c.source();
    if same(parent, dispatch) {
        return dispatch
            .field_list(source, Field::Arguments)
            .into_iter()
            .flatten()
            .any(|argument| same(&argument, node));
    }
    if !c.is_member(Some(parent)) || !is_field(source, parent, Field::Object, node) {
        return false;
    }
    let key = c.key(parent, Field::Property);
    let written = (is_assign(grandparent, None)
        && grandparent.is_some_and(|it| is_field(source, it, Field::Left, parent)))
        || is_update(grandparent)
        || is_delete(grandparent);
    if written {
        return key.is_some_and(|key| key != "exports");
    }
    if key.is_none_or(|key| key != "exports") {
        return false;
    }
    // `module.exports` passed to the factory, or read after the dispatch ran.
    grandparent.is_some_and(|it| same(it, dispatch)) || parent.span().start > dispatch.span().end
}

/// Record `cache[key]` reads that initialize the loader's early-return
/// binding.
fn with_cache_reads<'a>(
    c: &Ctx<'_, 'a>,
    body: &Node<'a>,
    shape: LoaderShape<'a>,
) -> Option<LoaderShape<'a>> {
    let Some(cache_id) = shape.cache_id.clone() else {
        return Some(shape);
    };
    struct Scan<'s, 'c, 'a> {
        c: &'s Ctx<'c, 'a>,
        parameter_id: &'s str,
        cache_id: &'s str,
        sites: NodeSet,
        contained: bool,
    }
    impl<'a> AstVisitor<'a> for Scan<'_, '_, 'a> {
        fn skip(&mut self, node: &Node<'a>) -> bool {
            is_function(node)
        }
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _: &[Node<'a>]) {
            if node.babel_type() != "MemberExpression"
                || !keyed_slot(self.c, node, self.parameter_id)
                    .is_some_and(|key| key == self.cache_id)
            {
                return;
            }
            let read = parent.is_some_and(|parent| {
                parent.babel_type() == "VariableDeclarator"
                    && is_field(self.c.source(), parent, Field::Init, node)
            });
            if read || is_delete(parent) || self.sites.contains(&node.key()) {
                self.sites.insert(node.key());
            } else {
                self.contained = false;
            }
        }
    }
    let mut scan = Scan {
        c,
        parameter_id: &shape.parameter_id,
        cache_id: &cache_id,
        sites: shape.cache_sites.clone(),
        contained: true,
    };
    let _: ControlFlow<()> = traverse(*body, c.source(), &mut scan, || ControlFlow::Continue(()));
    if !scan.contained {
        return None;
    }
    let sites = scan.sites;
    Some(LoaderShape {
        cache_sites: sites,
        ..shape
    })
}

/// Accept `module.exports` or `cache[key].exports` read through a stable
/// binding.
fn returns_module_exports<'a>(
    c: &Ctx<'_, 'a>,
    argument: Option<Node<'a>>,
    shape: &LoaderShape<'a>,
) -> bool {
    let source = c.source();
    let (value, before) = match argument {
        Some(sequence) if sequence.babel_type() == "SequenceExpression" => {
            let mut expressions: Vec<Node<'a>> = sequence
                .field_list(source, Field::Expressions)
                .into_iter()
                .flatten()
                .collect();
            let value = expressions.pop();
            (value, expressions)
        }
        other => (other, Vec::new()),
    };
    if !before
        .iter()
        .all(|expression| side_effect_before_return(c, expression, shape))
    {
        return false;
    }
    let Some(value) = value.filter(|it| it.babel_type() == "MemberExpression") else {
        return false;
    };
    let Some(object) = c.identifier(value.field(source, Field::Object)) else {
        return false;
    };
    if c.key(&value, Field::Property)
        .is_none_or(|key| key != "exports")
    {
        return false;
    }
    let Some(id) = c.binding_of(&object) else {
        return false;
    };
    if id == shape.module_id {
        return true;
    }
    let Some(cache_id) = &shape.cache_id else {
        return false;
    };
    let definitions = c.semantics.binding_by_id(id).map(|it| it.definitions);
    c.semantics
        .stable_initializer(id)
        .is_some_and(|initializer| {
            definitions == Some(1)
                && initializer.projection_len == 0
                && keyed_slot(c, &initializer.node, &shape.parameter_id)
                    .is_some_and(|key| key == *cache_id)
        })
}

/// The dispatch itself, or a write to a module member other than `exports`.
fn side_effect_before_return<'a>(
    c: &Ctx<'_, 'a>,
    expression: &Node<'a>,
    shape: &LoaderShape<'a>,
) -> bool {
    if same(expression, &shape.dispatch) {
        return true;
    }
    if !is_assign(Some(expression), None) {
        return false;
    }
    let Some(left) = expression
        .field(c.source(), Field::Left)
        .filter(|it| c.is_member(Some(it)))
    else {
        return false;
    };
    let Some(object) = c.identifier(left.field(c.source(), Field::Object)) else {
        return false;
    };
    if c.binding_of(&object) != Some(shape.module_id.as_str()) {
        return false;
    }
    c.key(&left, Field::Property)
        .is_some_and(|key| key != "exports")
}

/// The binding of `owner` in `owner[key]` when `key` is the loader parameter.
fn keyed_slot<'a>(c: &Ctx<'_, 'a>, node: &Node<'a>, parameter_id: &str) -> Option<String> {
    if !c.is_member(Some(node)) || !node.computed() {
        return None;
    }
    let object = c.identifier(node.field(c.source(), Field::Object))?;
    let property = c.identifier(node.field(c.source(), Field::Property))?;
    if c.binding_of(&property) != Some(parameter_id) {
        return None;
    }
    c.binding_of(&object).map(str::to_owned)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Table,
    Cache,
    Loader,
}

struct Use<'s, 'a> {
    node: &'s Node<'a>,
    parent: &'s Node<'a>,
    ancestors: &'s [Node<'a>],
}

impl<'a> Use<'_, 'a> {
    /// `ancestors.at(-n)`.
    fn at(&self, n: usize) -> Option<&Node<'a>> {
        self.ancestors
            .len()
            .checked_sub(n)
            .map(|index| &self.ancestors[index])
    }
}

fn references_are_contained<'a>(
    c: &Ctx<'_, 'a>,
    call: &Node<'a>,
    bootstrap: &Bootstrap<'a>,
    shape: &LoaderShape<'a>,
    loader_ids: &HashSet<String>,
) -> Option<BootstrapIntegrity> {
    let mut tracked: HashMap<String, Role> = HashMap::new();
    tracked.insert(bootstrap.table_binding_id.clone(), Role::Table);
    if let Some(cache_id) = &shape.cache_id {
        tracked.insert(cache_id.clone(), Role::Cache);
    }
    for id in loader_ids {
        tracked.insert(id.clone(), Role::Loader);
    }
    let names: HashSet<String> = tracked
        .keys()
        .filter_map(|id| c.semantics.binding_by_id(id).map(|it| it.name.clone()))
        .collect();
    struct Scan<'s, 'c, 'a> {
        c: &'s Ctx<'c, 'a>,
        shape: &'s LoaderShape<'a>,
        loader_ids: &'s HashSet<String>,
        tracked: &'s HashMap<String, Role>,
        names: &'s HashSet<String>,
        replaced: BTreeSet<String>,
        contained: bool,
    }
    impl<'a> AstVisitor<'a> for Scan<'_, '_, 'a> {
        fn skip(&mut self, _: &Node<'a>) -> bool {
            !self.contained
        }
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
            let Some(parent) = parent else { return };
            if node.babel_type() != "Identifier"
                || !node
                    .identifier_name()
                    .is_some_and(|name| self.names.contains(name))
            {
                return;
            }
            let grandparent = ancestors
                .len()
                .checked_sub(2)
                .map(|index| &ancestors[index]);
            if !is_referenced(self.c.source(), node, parent, grandparent) {
                return;
            }
            let Some(role) = self
                .c
                .binding_of(node)
                .and_then(|id| self.tracked.get(id))
                .copied()
            else {
                return;
            };
            let use_ = Use {
                node,
                parent,
                ancestors,
            };
            match role {
                Role::Loader => match exposed_table_use(self.c, &use_) {
                    Exposed::Escaped => self.contained = false,
                    _ => exposed_slot_write(self.c, &use_, &mut self.replaced),
                },
                role => {
                    self.contained = contained_use(self.c, role, &use_, self.shape, self.loader_ids)
                }
            }
        }
    }
    let mut scan = Scan {
        c,
        shape,
        loader_ids,
        tracked: &tracked,
        names: &names,
        replaced: BTreeSet::new(),
        contained: true,
    };
    let _: ControlFlow<()> = traverse(*call, c.source(), &mut scan, || ControlFlow::Continue(()));
    scan.contained.then_some(BootstrapIntegrity {
        replaced_keys: scan.replaced,
    })
}

/// The table is read only by the dispatch; the cache only by the loader's
/// own slot operations.
fn contained_use<'a>(
    c: &Ctx<'_, 'a>,
    role: Role,
    use_: &Use<'_, 'a>,
    shape: &LoaderShape<'a>,
    loader_ids: &HashSet<String>,
) -> bool {
    if role == Role::Table && shape.dispatches.contains(&use_.node.key()) {
        return true;
    }
    if role == Role::Cache && shape.cache_sites.contains(&use_.parent.key()) {
        return true;
    }
    is_runtime_exposure(
        c,
        use_,
        if role == Role::Table { "m" } else { "c" },
        loader_ids,
    )
}

/// `loader.m = table` or `loader.c = cache`.
fn is_runtime_exposure<'a>(
    c: &Ctx<'_, 'a>,
    use_: &Use<'_, 'a>,
    key: &str,
    loader_ids: &HashSet<String>,
) -> bool {
    let source = c.source();
    let parent = use_.parent;
    if !is_assign(Some(parent), Some("=")) || !is_field(source, parent, Field::Right, use_.node) {
        return false;
    }
    let Some(left) = parent
        .field(source, Field::Left)
        .filter(|it| c.is_member(Some(it)))
    else {
        return false;
    };
    let Some(object) = c.identifier(left.field(source, Field::Object)) else {
        return false;
    };
    c.key(&left, Field::Property)
        .is_some_and(|value| value == key)
        && loader_ids.contains(c.binding_of(&object).unwrap_or(""))
}

enum Exposed {
    Other,
    Contained,
    Escaped,
}

fn is_exposure_member<'a>(c: &Ctx<'_, 'a>, use_: &Use<'_, 'a>) -> bool {
    c.is_member(Some(use_.parent))
        && is_field(c.source(), use_.parent, Field::Object, use_.node)
        && c.key(use_.parent, Field::Property)
            .is_some_and(|key| key == "m" || key == "c")
}

/// `loader.m`/`loader.c` may only be assigned or indexed directly.
fn exposed_table_use<'a>(c: &Ctx<'_, 'a>, use_: &Use<'_, 'a>) -> Exposed {
    let source = c.source();
    if !is_exposure_member(c, use_) {
        return Exposed::Other;
    }
    let parent = use_.parent;
    let outer = use_.at(2);
    let assigned = is_assign(outer, Some("="))
        && outer.is_some_and(|it| is_field(source, it, Field::Left, parent));
    let indexed = c.is_member(outer)
        && outer.is_some_and(|it| is_field(source, it, Field::Object, parent) && it.computed());
    if assigned {
        return Exposed::Contained;
    }
    if !indexed {
        return Exposed::Escaped;
    }
    let (Some(outer), member, target) = (outer, use_.at(3), use_.at(4)) else {
        return Exposed::Escaped;
    };
    let entry_written = c.is_member(member)
        && member.is_some_and(|member| {
            is_field(source, member, Field::Object, outer)
                && ((is_assign(target, None)
                    && target.is_some_and(|it| is_field(source, it, Field::Left, member)))
                    || is_update(target)
                    || is_delete(target))
        });
    if entry_written {
        Exposed::Escaped
    } else {
        Exposed::Contained
    }
}

/// `loader.m[key] = factory` or `delete loader.c[key]` replaces a literal
/// slot; runtime keys are chunk installation.
fn exposed_slot_write<'a>(c: &Ctx<'_, 'a>, use_: &Use<'_, 'a>, replaced: &mut BTreeSet<String>) {
    let source = c.source();
    let parent = use_.parent;
    let (Some(slot), write) = (use_.at(2), use_.at(3)) else {
        return;
    };
    if !is_exposure_member(c, use_)
        || !c.is_member(Some(slot))
        || !is_field(source, slot, Field::Object, parent)
        || !((is_assign(write, None)
            && write.is_some_and(|it| is_field(source, it, Field::Left, slot)))
            || is_delete(write)
            || is_update(write))
    {
        return;
    }
    let Some(property) = slot.field(source, Field::Property) else {
        return;
    };
    let key = if slot.computed() {
        argument_value(source, Some(property)).map(|key| key.into_owned())
    } else {
        static_property_key(source, property, false).and_then(|key| key.try_to_string().ok())
    };
    if let Some(key) = key {
        replaced.insert(key);
    }
}
