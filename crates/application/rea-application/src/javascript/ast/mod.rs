//! Babel-shaped analysis view over the oxc AST (port plan F0).
//!
//! The TS graph producer reads Babel ASTs: node type names, `VISITOR_KEYS`
//! child order, UTF-16 positions, `extra.parenthesized` and node-identity
//! side tables. This module is the single owner of that mapping so analysis
//! packages do not reinterpret oxc differently:
//!
//! - [`Node`]: one Babel node (type name, span, parenthesized flag, key);
//!   vocabulary mapping in [`node`].
//! - [`Node::children`]: `t.VISITOR_KEYS` order; [`Node::field`] and the
//!   scalar accessors read named Babel fields as the same views.
//! - [`traverse`]: `traverseJavaScriptAst` with ancestors and checkpoints.
//! - [`AstContext`]: UTF-16 `start`/`end`/`loc`/slices over the parser's
//!   [`PositionIndex`](crate::javascript::parser::PositionIndex), and
//!   [`NodeMap`]/[`NodeSet`] keyed by [`NodeKey`] (oxc `NodeId` + role).
//!
//! Parse analysis inputs with
//! [`parse_javascript_analysis_program`](crate::javascript::parser::parse_javascript_analysis_program)
//! so parentheses are retained and `parenthesized` is exact. Agreement with
//! Babel is checked by the node-sequence harness in
//! `.cache/rust-migration/js-parse-diff/` (`sequence.mjs`).

mod children;
mod context;
mod fields;
pub mod node;
mod parents;
mod traverse;

pub use context::{AstContext, NodeMap, NodeSet};
pub use fields::Field;
pub use node::{Node, NodeKey, NodeKind, Role};
pub use parents::NodeParents;
pub use traverse::{AstVisitor, TRAVERSAL_CHECKPOINT_INTERVAL, traverse};

#[cfg(test)]
mod tests;
