//! Port of `javascriptSemanticState.ts`: the scope/binding records built by
//! the definitions pass and the lexical lookups over them.
//!
//! Records keep TS field order and semantics. Node-identity side tables
//! (`WeakMap`/`WeakSet` in TS) key on [`NodeKey`]; maps whose iteration
//! order is observable (`scopesById`, `bindingsById`, `bindingWrites`, scope
//! `bindings`) are [`InsertionMap`]s with JS `Map` semantics.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use indexmap::IndexMap;

use crate::javascript::ast::{AstContext, Field, Node, NodeKey, NodeMap, NodeParents, NodeSet};
use crate::javascript::parser::SourceRange;
use crate::javascript::static_analysis::semantics::BindingFacts;

use super::ast_values::{is_identifier_named, property_key_of, static_property_key, unwrapped};
use super::bundled_require_origin::BundledRequireProofCache;
use super::opaque_effects::OpaqueEffects;
use super::property_paths::PropertyPath;
use super::value_types::JsString;

/// A string-keyed map with JavaScript `Map` iteration order: first insertion
/// fixes a key's position; setting it again replaces the value in place.
#[derive(Clone, Debug)]
pub struct InsertionMap<V> {
    entries: IndexMap<String, V>,
}

impl<V> Default for InsertionMap<V> {
    fn default() -> Self {
        Self {
            entries: IndexMap::new(),
        }
    }
}

impl<V> InsertionMap<V> {
    pub fn get(&self, key: &str) -> Option<&V> {
        self.entries.get(key)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        self.entries.get_mut(key)
    }

    pub fn set(&mut self, key: String, value: V) {
        self.entries.insert(key, value);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &V)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value))
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, value)| value)
    }

    /// The entry for `key`, inserted with `default` when missing.
    pub fn entry_or(&mut self, key: &str, default: impl FnOnce() -> V) -> &mut V {
        if !self.entries.contains_key(key) {
            self.set(key.to_owned(), default());
        }
        self.get_mut(key).expect("inserted")
    }
}

/// Index of a scope in [`SemanticState::scopes`] (TS object identity).
pub type ScopeIndex = usize;
/// Index of a binding in [`SemanticState::bindings`] (TS object identity).
pub type BindingIndex = usize;

/// `JavaScriptSemanticScope["kind"]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeKind {
    Program,
    Function,
    Block,
    StaticBlock,
    Class,
    Catch,
}

impl ScopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Program => "program",
            Self::Function => "function",
            Self::Block => "block",
            Self::StaticBlock => "static-block",
            Self::Class => "class",
            Self::Catch => "catch",
        }
    }
}

/// `JavaScriptSemanticDefinition["kind"]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefinitionKind {
    Import,
    Variable,
    Parameter,
    Function,
    Class,
    Catch,
    Assignment,
}

impl DefinitionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Variable => "variable",
            Self::Parameter => "parameter",
            Self::Function => "function",
            Self::Class => "class",
            Self::Catch => "catch",
            Self::Assignment => "assignment",
        }
    }
}

/// `JavaScriptModuleResolutionMode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionMode {
    Import,
    Require,
    CompilerDependent,
}

impl ResolutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Require => "require",
            Self::CompilerDependent => "compiler-dependent",
        }
    }
}

/// `JavaScriptModuleOrigin`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleOrigin {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_mode: Option<ResolutionMode>,
    pub specifier: JsString,
    pub imported_path: Vec<JsString>,
}

/// `JavaScriptSemanticDefinition`.
#[derive(Clone, Debug)]
pub struct Definition {
    pub kind: DefinitionKind,
    pub location: SourceRange,
}

/// One destructuring/member projection step (`string | number | null`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProjectionKey {
    Name(JsString),
    Index(usize),
    /// A dynamic key (`null`).
    Dynamic,
}

/// `JavaScriptSemanticInitializer`.
#[derive(Clone, Debug)]
pub struct Initializer<'a> {
    /// Stable identity of the initializer record, distinct from its AST node.
    /// Zero is reserved for temporary origin records that are never stored on a
    /// binding's `initializers` list.
    pub record_id: usize,
    pub node: Node<'a>,
    pub projection: Vec<ProjectionKey>,
    /// The function body whose entry copies a parameter (`entryBody`).
    pub entry_body: Option<Node<'a>>,
}

/// `copyKind` of a reference initializer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CopyKind {
    ObjectRest,
    ArrayRest,
}

impl CopyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObjectRest => "object-rest",
            Self::ArrayRest => "array-rest",
        }
    }
}

/// `JavaScriptSemanticReferenceInitializer`.
#[derive(Clone, Debug)]
pub struct ReferenceInitializer<'a> {
    pub node: Node<'a>,
    pub projection: Vec<ProjectionKey>,
    pub copy_kind: Option<CopyKind>,
    pub copy_projection_offset: Option<usize>,
    pub copy_excluded_keys: Option<Vec<JsString>>,
    pub copy_start_index: Option<usize>,
    pub fallback_sources: Option<Vec<Initializer<'a>>>,
    pub required_sources: Option<Vec<Initializer<'a>>>,
}

/// `declarationKinds` entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclarationKind {
    Var,
    Let,
    Const,
    Using,
    AwaitUsing,
}

impl DeclarationKind {
    pub fn parse(kind: &str) -> Option<Self> {
        Some(match kind {
            "var" => Self::Var,
            "let" => Self::Let,
            "const" => Self::Const,
            "using" => Self::Using,
            "await using" => Self::AwaitUsing,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Var => "var",
            Self::Let => "let",
            Self::Const => "const",
            Self::Using => "using",
            Self::AwaitUsing => "await using",
        }
    }
}

/// `JavaScriptSemanticBindingState`, as far as the definitions pass fills it.
/// `memberWrites`/`escapedPaths` (member mutation facts) and `hostOrigin`
/// (CommonJS receivers) are added by the packages that produce them.
#[derive(Clone, Debug)]
pub struct BindingState<'a> {
    pub binding_id: String,
    pub scope_id: String,
    pub name: String,
    pub kind: DefinitionKind,
    /// Insertion-ordered set.
    pub declaration_kinds: Vec<DeclarationKind>,
    pub mutable: bool,
    /// Ordered member mutations whose receiver originated from this binding.
    pub member_writes: Vec<MemberEffect<'a>>,
    /// Ordered escapes of references originating from this binding.
    pub escaped_paths: Vec<MemberEffect<'a>>,
    pub definitions: Vec<Definition>,
    pub initializers: Vec<Initializer<'a>>,
    pub reference_initializers: Vec<ReferenceInitializer<'a>>,
    pub direct_origins: Vec<ModuleOrigin>,
    /// An ECMAScript import that exists at runtime.
    pub runtime_import: bool,
}

/// A member mutation or escape associated with a projected property path.
#[derive(Clone, Debug)]
pub struct MemberEffect<'a> {
    pub path: PropertyPath,
    pub node: Option<Node<'a>>,
}

/// A mutation or escape of a value exported by a required module.
#[derive(Clone, Debug)]
pub struct RequiredModuleEffect<'a> {
    pub path: PropertyPath,
    pub node: Option<Node<'a>>,
    pub kind: RequiredModuleEffectKind,
}

#[derive(Clone, Debug, Default)]
pub struct RequiredModuleEffects<'a> {
    entries: Vec<(JsString, Vec<RequiredModuleEffect<'a>>)>,
}

impl<'a> RequiredModuleEffects<'a> {
    pub fn entry_or(&mut self, key: &JsString) -> &mut Vec<RequiredModuleEffect<'a>> {
        if let Some(index) = self.entries.iter().position(|(entry, _)| entry == key) {
            return &mut self.entries[index].1;
        }
        self.entries.push((key.clone(), Vec::new()));
        &mut self.entries.last_mut().expect("inserted").1
    }

    pub fn iter(&self) -> impl Iterator<Item = (&JsString, &[RequiredModuleEffect<'a>])> {
        self.entries
            .iter()
            .map(|(key, effects)| (key, effects.as_slice()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequiredModuleEffectKind {
    Write,
    Escape,
}

/// `JavaScriptSemanticScopeState`.
#[derive(Clone, Debug)]
pub struct ScopeState<'a> {
    pub scope_id: String,
    /// The owner index is used for ancestry. Public scope IDs are derived
    /// from the indexed scope only when projecting the analysis result.
    pub parent_scope: Option<ScopeIndex>,
    pub kind: ScopeKind,
    pub location: SourceRange,
    pub bindings_complete: bool,
    pub bindings: InsertionMap<BindingIndex>,
    /// Object environment introduced by `with`, active only for its body.
    pub dynamic_with_statement: Option<Node<'a>>,
}

/// The definitions-pass slice of `JavaScriptSemanticAnalysisState`.
pub struct SemanticState<'a> {
    /// The parsed source: positions, ranges and text.
    pub context: AstContext<'a>,
    pub source: &'a str,
    pub program: Node<'a>,
    /// Babel `program.sourceType === "script"`.
    pub script: bool,
    pub static_import_resolution_mode: ResolutionMode,
    pub parents: NodeParents<'a>,
    pub scopes: Vec<ScopeState<'a>>,
    pub scopes_by_id: InsertionMap<ScopeIndex>,
    /// Scope boundaries plus descendants resolved on demand (memo).
    pub scope_by_node: RefCell<NodeMap<ScopeIndex>>,
    pub bindings: Vec<BindingState<'a>>,
    pub bindings_by_id: InsertionMap<BindingIndex>,
    /// Resolved identifier writes at their exact source sites.
    pub binding_writes: InsertionMap<Vec<Node<'a>>>,
    /// Unbound identifier writes, for capture ordering.
    pub ambient_binding_writes: InsertionMap<Vec<Node<'a>>>,
    /// Source-local writes to global, import-meta, and CommonJS identities.
    pub ambient_writes: super::property_paths::SemanticPropertyPathCoverage,
    /// Ambient identities passed to calls whose effects are not evaluated.
    pub ambient_escapes: super::property_paths::SemanticPropertyPathCoverage,
    /// Ordered source effects retained at their original write sites.
    pub ambient_write_effects: Vec<super::ambient_writes::AmbientWriteEffect<'a>>,
    /// Required-module effects retained in specifier insertion order.
    pub required_module_effects: RequiredModuleEffects<'a>,
    /// Callables whose returned-reference projection had to widen. The
    /// returned-reference producer owns this evidence; coverage reads it only
    /// after all value and ambient consumers have run.
    pub returned_reference_widenings: RefCell<Vec<crate::javascript::parser::SourceRange>>,
    /// Initializer expressions whose write enclosing control flow can skip.
    pub conditionally_skipped: NodeSet,
    /// `None` is TS `undefined` (possible mutation observed).
    pub prototype_require_mutation_observed: Option<bool>,
    pub prototype_enumeration_may_affect: Option<bool>,
    /// `opaqueEffects.mayReferenceGlobalEval`.
    pub may_reference_global_eval: bool,
    /// Direct `eval(...)` candidates with their scope id, in source order,
    /// for `indexSemanticOpaqueEffects` (opaque-effects package).
    pub opaque_candidates: Vec<(Node<'a>, String)>,
    /// Source-derived global-eval sites. Scope and binding facts are complete
    /// before semantic consumers run, and later semantic passes only append
    /// member effects; neither changes the inputs used by this cache.
    pub(crate) global_eval_sites_cache: RefCell<Option<std::rc::Rc<Vec<Node<'a>>>>>,
    /// Direct-eval indexes are immutable after definitions and shared by all
    /// value and provenance queries in this semantic state.
    pub(crate) opaque_effects_cache: RefCell<Option<Rc<OpaqueEffects<'a>>>>,
    /// Binding facts are immutable after the definitions pass.  Consumers
    /// such as bundled-loader proof may ask for them from many AST nodes; the
    /// owner keeps one shared map instead of rebuilding and cloning every
    /// binding record for each proof attempt.
    pub(crate) state_facts_cache: RefCell<Option<Rc<HashMap<String, BindingFacts>>>>,
    /// Scope lookup results are enabled only after definitions have finished
    /// mutating the scope and binding tables.
    pub(crate) binding_lookup_cache: RefCell<BindingLookupCache>,
    /// Pure direct return/yield syntax facts, shared by semantic consumers.
    pub(crate) callable_result_cache:
        RefCell<HashMap<NodeKey, Rc<Vec<super::callable_results::CallableResultExpression<'a>>>>>,
    /// Source-order facts are immutable after definitions; all semantic
    /// consumers in this analysis share the owner cache instead of rebuilding
    /// ancestry walks for each initializer read.
    pub(crate) statement_position_cache:
        RefCell<super::mutation_initializers::StatementPositionCache>,
    /// Getter expansion limits recorded in first-observed order.
    pub getter_resource_limits: RefCell<Vec<super::value_types::ResourceLimit>>,
    /// Value interpretation limits recorded in first-observed order.
    pub value_resource_limits: RefCell<Vec<super::value_types::ResourceLimit>>,
    /// Effect-dependent constant values and immutable binding identity proofs.
    pub(crate) value_caches: RefCell<super::values::ValueCaches>,
    /// Re-entrant cache for the source-derived writes to the CommonJS
    /// wrapper's `module.require` slot. `Building` is published before the
    /// scan so interop/require-origin recursion fails closed without
    /// retaining a partial result.
    pub module_require_writes: RefCell<ModuleRequireWritesCache<'a>>,
    /// Positive and negative bundled-loader proof results for this analysis.
    pub(crate) bundled_require_proofs: RefCell<BundledRequireProofCache<'a>>,
    /// Monotonic identity source for stored initializer records.
    pub(crate) next_initializer_id: usize,
}

const MAX_BINDING_LOOKUP_CACHE_ENTRIES: usize = 65_536;
const MAX_BINDING_LOOKUP_CACHE_BYTES: usize = 8 * 1024 * 1024;
const BINDING_LOOKUP_CACHE_ENTRY_OVERHEAD: usize = 64;

#[derive(Debug, Default)]
pub(crate) struct BindingLookupCache {
    enabled: bool,
    entries: HashMap<Option<ScopeIndex>, HashMap<String, CachedBindingLookup>>,
    entry_count: usize,
    estimated_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
struct CachedBindingLookup {
    prototype_require_mutation_observed: Option<bool>,
    result: BindingLookup,
}

impl BindingLookupCache {
    fn enable(&mut self) {
        self.enabled = true;
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.entry_count = 0;
        self.estimated_bytes = 0;
    }

    fn get(
        &self,
        scope: Option<ScopeIndex>,
        name: &str,
        prototype_require_mutation_observed: Option<bool>,
    ) -> Option<BindingLookup> {
        if !self.enabled {
            return None;
        }
        self.entries.get(&scope).and_then(|entries| {
            entries.get(name).and_then(|cached| {
                (cached.prototype_require_mutation_observed == prototype_require_mutation_observed)
                    .then_some(cached.result)
            })
        })
    }

    fn insert(
        &mut self,
        scope: Option<ScopeIndex>,
        name: &str,
        prototype_require_mutation_observed: Option<bool>,
        result: BindingLookup,
    ) {
        if !self.enabled {
            return;
        }

        if let Some(entries) = self.entries.get_mut(&scope)
            && let Some(cached) = entries.get_mut(name)
        {
            cached.prototype_require_mutation_observed = prototype_require_mutation_observed;
            cached.result = result;
            return;
        }

        let entry_bytes = BINDING_LOOKUP_CACHE_ENTRY_OVERHEAD.saturating_add(name.len());
        if entry_bytes > MAX_BINDING_LOOKUP_CACHE_BYTES {
            return;
        }
        if self.entry_count >= MAX_BINDING_LOOKUP_CACHE_ENTRIES
            || self.estimated_bytes.saturating_add(entry_bytes) > MAX_BINDING_LOOKUP_CACHE_BYTES
        {
            self.clear();
        }

        let entries = self.entries.entry(scope).or_default();
        entries.insert(
            name.to_owned(),
            CachedBindingLookup {
                prototype_require_mutation_observed,
                result,
            },
        );
        self.entry_count += 1;
        self.estimated_bytes = self.estimated_bytes.saturating_add(entry_bytes);
    }
}

#[derive(Debug)]
pub enum ModuleRequireWritesCache<'a> {
    Empty,
    Building,
    Ready(Vec<Node<'a>>),
}

impl<'a> SemanticState<'a> {
    pub(crate) fn enable_binding_lookup_cache(&self) {
        self.binding_lookup_cache.borrow_mut().enable();
    }

    pub(crate) fn invalidate_binding_lookup_cache(&mut self) {
        self.binding_lookup_cache.borrow_mut().clear();
    }

    pub(crate) fn callable_result_expressions(
        &self,
        callable: &Node<'a>,
    ) -> Rc<Vec<super::callable_results::CallableResultExpression<'a>>> {
        if let Some(results) = self.callable_result_cache.borrow().get(&callable.key()) {
            return Rc::clone(results);
        }
        let results = Rc::new(super::callable_results::callable_result_expressions(
            self.source,
            callable,
        ));
        self.callable_result_cache
            .borrow_mut()
            .insert(callable.key(), Rc::clone(&results));
        results
    }

    /// Select binding facts at a read site using this analysis' shared
    /// source-order cache.
    pub(crate) fn semantic_binding_at_read<'b>(
        &self,
        binding: &'b BindingState<'a>,
        read: Node<'a>,
    ) -> super::mutation_initializers::SemanticBindingRead<'b, 'a> {
        super::mutation_initializers::semantic_binding_at_read_cached(
            &mut self.statement_position_cache.borrow_mut(),
            binding,
            read,
            &self.parents,
            self.source,
        )
    }

    pub(crate) fn semantic_capture_position(
        &self,
        node: Node<'a>,
    ) -> Option<super::mutation_initializers::StatementPosition> {
        super::mutation_initializers::cached_semantic_capture_position(
            &mut self.statement_position_cache.borrow_mut(),
            node,
            &self.parents,
            self.source,
        )
    }

    pub(crate) fn semantic_binding_precedes_capture(
        &self,
        binding: &BindingState<'a>,
        capture: Node<'a>,
    ) -> bool {
        super::mutation_initializers::cached_semantic_binding_precedes_capture(
            &mut self.statement_position_cache.borrow_mut(),
            binding,
            capture,
            &self.parents,
            self.source,
        )
    }

    pub(crate) fn semantic_escape_follows_capture(
        &self,
        binding: &BindingState<'a>,
        capture: Node<'a>,
        escape: Option<Node<'a>>,
    ) -> bool {
        super::mutation_initializers::cached_semantic_escape_follows_capture(
            &mut self.statement_position_cache.borrow_mut(),
            binding,
            capture,
            escape,
            &self.parents,
            self.source,
        )
    }

    pub(crate) fn semantic_binding_effect_follows_capture(
        &self,
        binding: &BindingState<'a>,
        capture: Node<'a>,
        effect: Node<'a>,
    ) -> bool {
        super::mutation_initializers::cached_semantic_binding_effect_follows_capture(
            &mut self.statement_position_cache.borrow_mut(),
            binding,
            capture,
            effect,
            &self.parents,
            self.source,
        )
    }

    pub(crate) fn top_level_effect_follows_capture(
        &self,
        capture: Node<'a>,
        effect: Option<Node<'a>>,
    ) -> bool {
        super::mutation_initializers::cached_top_level_effect_follows_capture(
            &mut self.statement_position_cache.borrow_mut(),
            capture,
            effect,
            &self.parents,
            self.source,
        )
    }

    /// Record a value resource limit once, preserving observation order.
    pub fn record_value_resource_limit(&self, limit: super::value_types::ResourceLimit) {
        let mut limits = self.value_resource_limits.borrow_mut();
        if !limits.contains(&limit) {
            limits.push(limit);
        }
    }

    /// Record a getter resource limit once, preserving source observation order.
    pub fn record_getter_resource_limit(&self, limit: super::value_types::ResourceLimit) {
        let mut limits = self.getter_resource_limits.borrow_mut();
        if !limits.contains(&limit) {
            limits.push(limit);
        }
    }

    pub(crate) fn allocate_initializer_id(&mut self) -> usize {
        let id = self.next_initializer_id;
        self.next_initializer_id = self.next_initializer_id.saturating_add(1);
        id
    }
}

/// `SemanticBindingLookup`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingLookup {
    Binding(BindingIndex),
    UncertainBinding(BindingIndex),
    Ambient,
    UncertainAmbient,
    Captured,
    Unknown,
}

impl BindingLookup {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Binding(_) => "binding",
            Self::UncertainBinding(_) => "uncertain-binding",
            Self::Ambient => "ambient",
            Self::UncertainAmbient => "uncertain-ambient",
            Self::Captured => "captured",
            Self::Unknown => "unknown",
        }
    }

    /// The certain or possible owner (`"binding" in lookup`).
    pub fn binding(self) -> Option<BindingIndex> {
        match self {
            Self::Binding(index) | Self::UncertainBinding(index) => Some(index),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WithRequireLookup {
    Captures,
    Skips,
    Unknown,
}

/// A `with` object property name (`semanticWithPropertyName`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum WithPropertyName {
    Unscopables,
    Name(JsString),
    Dynamic,
}

/// A final-property search result: absent, unknown, or the value.
#[derive(Clone, Copy, Debug)]
enum FinalProperty<'a> {
    Missing,
    Unknown,
    Value(Node<'a>),
}

/// `semanticScopeId`.
pub fn scope_id(kind: ScopeKind, start: u32, end: u32) -> String {
    format!("scope:{}:{start}:{end}", kind.as_str())
}

/// `semanticBindingId`.
pub fn binding_id(scope_id: &str, name: &str) -> String {
    format!("{scope_id}:binding:{}", encode_uri_component(name))
}

/// JavaScript `encodeURIComponent` over UTF-16; lone surrogates cannot
/// occur in a Rust string.
pub fn encode_uri_component(text: &str) -> String {
    const UNRESERVED: &[u8] = b"-_.!~*'()";
    let mut out = String::with_capacity(text.len());
    let mut buffer = [0u8; 4];
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || (ch.is_ascii() && UNRESERVED.contains(&(ch as u8))) {
            out.push(ch);
        } else {
            for byte in ch.encode_utf8(&mut buffer).bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

impl<'a> SemanticState<'a> {
    pub fn scope(&self, index: ScopeIndex) -> &ScopeState<'a> {
        &self.scopes[index]
    }

    pub fn binding(&self, index: BindingIndex) -> &BindingState<'a> {
        &self.bindings[index]
    }

    /// `state.scopesById.get(scope.parentScopeId)`.
    pub fn parent_scope(&self, index: ScopeIndex) -> Option<ScopeIndex> {
        self.scopes[index].parent_scope
    }

    /// Whether a scope is the named ancestor or one of its descendants.
    pub fn scope_is_within(&self, scope_id: &str, ancestor_id: &str) -> bool {
        if scope_id == ancestor_id {
            return true;
        }

        let mut current = self
            .scopes_by_id
            .get(scope_id)
            .and_then(|index| self.parent_scope(*index));
        while let Some(index) = current {
            if self.scope(index).scope_id == ancestor_id {
                return true;
            }
            current = self.parent_scope(index);
        }
        false
    }

    pub fn parent_of(&self, node: &Node<'a>) -> Option<Node<'a>> {
        self.parents.get(&node.key()).copied()
    }

    /// `semanticScopeForNode`, memoizing the traversed ancestry.
    pub fn scope_for_node(&self, node: &Node<'a>) -> Option<ScopeIndex> {
        let mut memo = self.scope_by_node.borrow_mut();
        let mut candidate: Option<NodeKey> = Some(node.key());
        while let Some(key) = candidate {
            if let Some(&scope) = memo.get(&key) {
                let mut descendant = Some(node.key());
                while let Some(current) = descendant {
                    if current == key {
                        break;
                    }
                    memo.insert(current, scope);
                    descendant = self.parents.get(&current).map(Node::key);
                }
                return Some(scope);
            }
            candidate = self.parents.get(&key).map(Node::key);
        }
        None
    }

    /// `semanticBindingLookupFromScope`: certain and possible owners without
    /// discarding `with` uncertainty.
    pub fn lookup_from_scope(&self, scope: Option<ScopeIndex>, name: &str) -> BindingLookup {
        // A local declaration wins even in an incomplete object environment.
        // Read it directly instead of maintaining a second cached copy of
        // the scope's own binding table for every identifier in a large file.
        if let Some(binding) = scope.and_then(|index| self.scopes[index].bindings.get(name)) {
            return BindingLookup::Binding(*binding);
        }

        let prototype_require_mutation_observed = self.prototype_require_mutation_observed;
        if let Some(result) =
            self.binding_lookup_cache
                .borrow()
                .get(scope, name, prototype_require_mutation_observed)
        {
            return result;
        }

        let result = self.lookup_from_scope_uncached(scope, name);
        self.binding_lookup_cache.borrow_mut().insert(
            scope,
            name,
            prototype_require_mutation_observed,
            result,
        );
        result
    }

    fn lookup_from_scope_uncached(&self, scope: Option<ScopeIndex>, name: &str) -> BindingLookup {
        let mut uncertain = false;
        let mut scope = scope;
        while let Some(index) = scope {
            let current = &self.scopes[index];
            if let Some(&binding) = current.bindings.get(name) {
                return if uncertain {
                    BindingLookup::UncertainBinding(binding)
                } else {
                    BindingLookup::Binding(binding)
                };
            }
            if !current.bindings_complete {
                let Some(statement) = current.dynamic_with_statement else {
                    return BindingLookup::Unknown;
                };
                match self.with_require_lookup(&statement, name) {
                    WithRequireLookup::Captures => return BindingLookup::Captured,
                    WithRequireLookup::Unknown => uncertain = true,
                    WithRequireLookup::Skips => {}
                }
            }
            scope = self.parent_scope(index);
        }
        if uncertain {
            BindingLookup::UncertainAmbient
        } else {
            BindingLookup::Ambient
        }
    }

    /// `semanticBindingLookupAt`.
    pub fn lookup_at(&self, node: &Node<'a>, name: &str) -> BindingLookup {
        self.lookup_from_scope(self.scope_for_node(node), name)
    }

    /// `resolveSemanticBindingState`.
    pub fn resolve_binding(&self, node: &Node<'a>, name: &str) -> Option<BindingIndex> {
        match self.lookup_at(node, name) {
            BindingLookup::Binding(index) => Some(index),
            _ => None,
        }
    }

    /// `semanticResolutionBlocked`: an omitted or dynamic binding blocks a
    /// trustworthy miss.
    pub fn resolution_blocked(&self, node: &Node<'a>, name: &str) -> bool {
        !matches!(
            self.lookup_at(node, name),
            BindingLookup::Binding(_) | BindingLookup::Ambient
        )
    }

    /// `resolveSemanticBindingFromScope`.
    pub fn resolve_from_scope(&self, scope: ScopeIndex, name: &str) -> Option<BindingIndex> {
        match self.lookup_from_scope(Some(scope), name) {
            BindingLookup::Binding(index) => Some(index),
            _ => None,
        }
    }

    /// `semanticStableInitializer`: one unconditional source initializer.
    pub fn stable_initializer(&self, binding: BindingIndex) -> Option<&Initializer<'a>> {
        let binding = &self.bindings[binding];
        let first_kind = binding.definitions.first().map(|d| d.kind);
        let declared = (first_kind == Some(DefinitionKind::Variable)
            && binding
                .definitions
                .iter()
                .all(|d| d.kind == DefinitionKind::Variable))
            || (binding.definitions.len() == 1
                && matches!(
                    first_kind,
                    Some(DefinitionKind::Function | DefinitionKind::Class)
                ));
        match binding.initializers.as_slice() {
            [initializer]
                if declared && !self.conditionally_skipped.contains(&initializer.node.key()) =>
            {
                Some(initializer)
            }
            _ => None,
        }
    }

    /// `semanticVariableScope`: the function/program owner of a `var`.
    pub fn variable_scope(&self, scope: ScopeIndex, parent: Option<&Node<'a>>) -> ScopeIndex {
        let is_var = parent.is_some_and(|parent| {
            parent.babel_type() == "VariableDeclaration" && parent.declaration_kind() == Some("var")
        });
        if !is_var {
            return scope;
        }
        let mut candidate = scope;
        while matches!(
            self.scopes[candidate].kind,
            ScopeKind::Block | ScopeKind::Catch
        ) {
            match self.parent_scope(candidate) {
                Some(outer) => candidate = outer,
                None => break,
            }
        }
        candidate
    }

    /// `isUnshadowedGlobal`.
    pub fn is_unshadowed_global(&self, node: &Node<'a>, name: &str) -> bool {
        is_identifier_named(node, name)
            && match self.resolve_binding(node, name) {
                None => !self.resolution_blocked(node, name),
                Some(_) => self.is_unmodified_commonjs_wrapper_binding(node, name),
            }
    }

    /// `isUnmodifiedCommonJsWrapperBinding`.
    pub fn is_unmodified_commonjs_wrapper_binding(&self, node: &Node<'a>, name: &str) -> bool {
        self.commonjs_wrapper_binding_declaration(node, name)
            .is_some_and(|binding| self.bindings[binding].initializers.is_empty())
    }

    /// `commonJsWrapperBindingDeclaration`: program `var` redeclarations keep
    /// wrapper identity until a source write.
    pub fn commonjs_wrapper_binding_declaration(
        &self,
        node: &Node<'a>,
        name: &str,
    ) -> Option<BindingIndex> {
        if !self.script
            || !matches!(name, "module" | "exports" | "require")
            || !is_identifier_named(node, name)
        {
            return None;
        }
        let index = self.resolve_binding(node, name)?;
        let binding = &self.bindings[index];
        let scope = self.scopes_by_id.get(&binding.scope_id)?;
        (self.scopes[*scope].kind == ScopeKind::Program
            && !binding.declaration_kinds.is_empty()
            && binding
                .declaration_kinds
                .iter()
                .all(|kind| *kind == DeclarationKind::Var))
        .then_some(index)
    }

    /// `semanticWithRequireLookup`: only source-visible own `require`
    /// entries in a literal `with` object are classified.
    fn with_require_lookup(&self, statement: &Node<'a>, name: &str) -> WithRequireLookup {
        use WithRequireLookup as L;
        let source = self.source;
        if name != "require" {
            return L::Unknown;
        }
        let Some(object) = statement.field(source, Field::Object) else {
            return L::Unknown;
        };
        let object = unwrapped(source, object);
        if object.babel_type() != "ObjectExpression" {
            return L::Unknown;
        }
        let mut own_require = false;
        let mut has_unknown_own_properties = false;
        let mut prototype_is_null = false;
        let mut unknown_prototype = false;
        for property in object
            .field_list(source, Field::Properties)
            .into_iter()
            .flatten()
        {
            if property.babel_type() == "SpreadElement" {
                has_unknown_own_properties = true;
                continue;
            }
            match self.with_property_name(&property) {
                WithPropertyName::Name(key) if key == "require" => own_require = true,
                WithPropertyName::Name(key)
                    if key == "__proto__"
                        && property.babel_type() == "ObjectProperty"
                        && !property.computed()
                        && !property.shorthand() =>
                {
                    let prototype = property
                        .field(source, Field::Value)
                        .map(|value| unwrapped(source, value));
                    if prototype.is_some_and(|p| p.babel_type() == "NullLiteral") {
                        prototype_is_null = true;
                    } else {
                        unknown_prototype = true;
                    }
                }
                WithPropertyName::Dynamic if property.computed() => {
                    has_unknown_own_properties = true;
                }
                _ => {}
            }
        }
        let observed_inert = self.prototype_require_mutation_observed == Some(false);
        if own_require {
            let unscopables_value = match self.final_with_symbol_property(&object) {
                FinalProperty::Unknown => return L::Unknown,
                FinalProperty::Missing => {
                    return if prototype_is_null || (!unknown_prototype && observed_inert) {
                        L::Captures
                    } else {
                        L::Unknown
                    };
                }
                FinalProperty::Value(value) => value,
            };
            let unscopables = unwrapped(source, unscopables_value);
            if unscopables.babel_type() != "ObjectExpression" {
                return if is_with_primitive(source, &unscopables) {
                    L::Captures
                } else {
                    L::Unknown
                };
            }
            return match final_with_string_property(source, &unscopables, "require") {
                FinalProperty::Unknown => L::Unknown,
                FinalProperty::Missing => match with_prototype_kind(source, &unscopables) {
                    WithPrototype::Null => L::Captures,
                    WithPrototype::Ordinary if observed_inert => L::Captures,
                    _ => L::Unknown,
                },
                FinalProperty::Value(entry) => match with_static_truthiness(source, entry) {
                    Some(true) => L::Skips,
                    Some(false) => L::Captures,
                    None => L::Unknown,
                },
            };
        }
        if has_unknown_own_properties || unknown_prototype {
            return L::Unknown;
        }
        if prototype_is_null {
            return L::Skips;
        }
        if observed_inert { L::Skips } else { L::Unknown }
    }

    /// `semanticWithPropertyName` for an object member.
    fn with_property_name(&self, property: &Node<'a>) -> WithPropertyName {
        let source = self.source;
        let Some(key) = property.field(source, Field::Key) else {
            return WithPropertyName::Dynamic;
        };
        let computed = property.computed();
        if computed && key.babel_type() == "MemberExpression" && !key.computed() {
            let object = key.field(source, Field::Object);
            let property_name = key
                .field(source, Field::Property)
                .and_then(|name| static_property_key(source, name, false));
            if let Some(object) = object
                && is_identifier_named(&object, "Symbol")
                && property_name.is_some_and(|name| name == "unscopables")
                && self.resolve_binding(&object, "Symbol").is_none()
                && !self.resolution_blocked(&object, "Symbol")
            {
                return WithPropertyName::Unscopables;
            }
        }
        match static_property_key(source, key, computed) {
            Some(name) => WithPropertyName::Name(name),
            None => WithPropertyName::Dynamic,
        }
    }

    /// `finalSemanticWithSymbolProperty`.
    fn final_with_symbol_property(&self, object: &Node<'a>) -> FinalProperty<'a> {
        let source = self.source;
        let properties = object.field_list(source, Field::Properties);
        for property in properties.into_iter().rev() {
            let Some(property) = property.filter(|p| p.babel_type() != "SpreadElement") else {
                return FinalProperty::Unknown;
            };
            match self.with_property_name(&property) {
                WithPropertyName::Unscopables => {
                    return match property.babel_type() {
                        "ObjectProperty" => property
                            .field(source, Field::Value)
                            .map_or(FinalProperty::Unknown, FinalProperty::Value),
                        _ => FinalProperty::Unknown,
                    };
                }
                WithPropertyName::Dynamic if property.computed() => return FinalProperty::Unknown,
                _ => {}
            }
        }
        FinalProperty::Missing
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WithPrototype {
    Null,
    Ordinary,
    Other,
}

/// `semanticWithPrototypeKind`.
fn with_prototype_kind<'a>(source: &'a str, object: &Node<'a>) -> WithPrototype {
    for property in object
        .field_list(source, Field::Properties)
        .into_iter()
        .flatten()
    {
        if property.babel_type() == "ObjectProperty"
            && !property.computed()
            && !property.shorthand()
            && property
                .field(source, Field::Key)
                .is_some_and(|key| is_identifier_named(&key, "__proto__"))
        {
            let value = property
                .field(source, Field::Value)
                .map(|value| unwrapped(source, value));
            return if value.is_some_and(|v| v.babel_type() == "NullLiteral") {
                WithPrototype::Null
            } else {
                WithPrototype::Other
            };
        }
    }
    WithPrototype::Ordinary
}

/// `finalSemanticWithStringProperty`.
fn final_with_string_property<'a>(
    source: &'a str,
    object: &Node<'a>,
    sought: &str,
) -> FinalProperty<'a> {
    let properties = object.field_list(source, Field::Properties);
    for property in properties.into_iter().rev() {
        let Some(property) = property.filter(|p| p.babel_type() != "SpreadElement") else {
            return FinalProperty::Unknown;
        };
        let name = property_key_of(source, &property);
        if name.as_ref().is_some_and(|name| name == sought) {
            return match property.babel_type() {
                "ObjectProperty" => property
                    .field(source, Field::Value)
                    .map_or(FinalProperty::Unknown, FinalProperty::Value),
                _ => FinalProperty::Unknown,
            };
        }
        if name.is_none() && property.computed() {
            return FinalProperty::Unknown;
        }
    }
    FinalProperty::Missing
}

/// `semanticWithStaticTruthiness`.
fn with_static_truthiness<'a>(source: &'a str, node: Node<'a>) -> Option<bool> {
    let value = unwrapped(source, node);
    match value.babel_type() {
        "BooleanLiteral" => value.boolean_value(),
        "NullLiteral" => Some(false),
        "StringLiteral" => value.string_value().map(|text| !text.is_empty()),
        "NumericLiteral" => value.numeric_value().map(|v| v != 0.0 && !v.is_nan()),
        "ObjectExpression"
        | "ArrayExpression"
        | "FunctionExpression"
        | "ArrowFunctionExpression" => Some(true),
        _ => None,
    }
}

/// `isSemanticWithPrimitive`.
fn is_with_primitive<'a>(source: &'a str, node: &Node<'a>) -> bool {
    match node.babel_type() {
        "NullLiteral" | "BooleanLiteral" | "StringLiteral" | "NumericLiteral" | "BigIntLiteral" => {
            true
        }
        "UnaryExpression" => {
            node.operator() == Some("-")
                && node.field(source, Field::Argument).is_some_and(|argument| {
                    matches!(argument.babel_type(), "NumericLiteral" | "BigIntLiteral")
                })
        }
        _ => false,
    }
}
