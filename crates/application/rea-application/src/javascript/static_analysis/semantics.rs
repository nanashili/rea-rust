//! The semantic seam: the only facts these packages read from the semantic
//! core (`JavaScriptSemanticAnalysisState` in TS).

use crate::javascript::ast::Node;
use crate::javascript::contracts::static_analysis::SourceRange;

/// The parts of one `JavaScriptSemanticBindingState` read here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingFacts {
    pub binding_id: String,
    pub name: String,
    pub mutable: bool,
    /// `scopesById.get(binding.scopeId)?.kind`.
    pub scope_kind: Option<String>,
    /// `definitions.length`.
    pub definitions: usize,
    /// `initializers.length`.
    pub initializers: usize,
}

/// `semanticStableInitializer(binding, state)`: its node and the length of
/// its projection (`initializer.projection.length`).
#[derive(Clone, Copy, Debug)]
pub struct StableInitializer<'a> {
    pub node: Node<'a>,
    pub projection_len: usize,
}

/// One `JavaScriptSemanticReference`, as read by the GraphQL ownership proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticReference {
    pub name: String,
    pub binding_id: Option<String>,
    pub role: String,
    pub resolution: String,
    pub location: SourceRange,
}

/// Semantic answers for one analysis. Implementations own their caches;
/// every method is a pure query for the analysis lifetime.
pub trait StaticSemantics<'a> {
    /// `resolveSemanticBindingState(state, identifier, identifier.name)`.
    fn binding(&self, identifier: &Node<'a>) -> Option<&BindingFacts>;
    /// `state.bindingsById.get(id)`.
    fn binding_by_id(&self, id: &str) -> Option<&BindingFacts>;
    /// `semanticStableInitializer(state.bindingsById.get(id), state)`.
    fn stable_initializer(&self, id: &str) -> Option<StableInitializer<'a>>;
    /// `state.parentsByNode.get(node)`.
    fn parent(&self, node: &Node<'a>) -> Option<Node<'a>>;
    /// `program.sourceType === "module"`.
    fn is_module(&self) -> bool;
    /// `index.referencesSteps()`: every semantic reference, in IR order.
    fn references(&self) -> Vec<SemanticReference>;

    /// `resolveSemanticBindingState(...)?.bindingId`.
    fn binding_id(&self, identifier: &Node<'a>) -> Option<&str> {
        self.binding(identifier)
            .map(|binding| binding.binding_id.as_str())
    }
}
