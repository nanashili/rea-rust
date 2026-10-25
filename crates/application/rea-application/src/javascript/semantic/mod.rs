//! Source-local semantic analysis over the Babel-shaped view in
//! [`crate::javascript::ast`] and keyed by oxc `NodeId`s through
//! [`NodeKey`](crate::javascript::ast::NodeKey).
//!
//! REA does not use a generic scope analysis: it splits parameter and body
//! environments, adds `:with` dynamic scopes and `:function-name` scopes,
//! evaluates computed method keys in the outer scope and keeps every write
//! site. The overlay therefore reproduces `collectDefinitionsSteps`
//! directly (same DFS, same IDs, same record order) instead of translating
//! `oxc_semantic` scopes, whose boundaries and hoisting differ.
//!
//! - [`definitions::collect_definitions`]: `createState` +
//!   `collectDefinitionsSteps`.
//! - [`state`]: the records and lexical lookups (`javascriptSemanticState`).
//! - [`ast_values`], [`evaluation_order`], [`callable_results`],
//!   [`control_flow`]: shared AST interpretation.
//! - [`callable_stack`], [`objects`], [`iteration_sources`]: callable ownership
//!   and syntax-derived property and iteration operations.
//! - [`value_types`], [`coverage`], [`slots`], [`limits`]: canonical value,
//!   uncertainty, and resource-bound contracts.
//! - [`mutation_initializers`], [`returned_references`], [`call_resolution`]:
//!   source-order binding selection and conservative local resolution.
//!
//! These passes are the production semantic source producer used by the
//! JavaScript application workflow. Unsupported or resource-bounded facts
//! remain explicit in the emitted coverage and unknowns; differential parity
//! verification is still a separate requirement.
//!
//! Agreement with TS is checked by `.cache/rust-migration/js-semantic-diff/`.

pub mod ambient_writes;
pub mod analysis;
pub mod ast_values;
pub mod async_effects;
pub mod bundled_require_origin;
pub mod call_resolution;
pub mod callable_results;
pub mod callable_stack;
pub mod calls;
pub mod child_processes;
pub mod commonjs_export_receivers;
pub mod control_flow;
pub mod coverage;
pub mod data_effect_helpers;
pub mod data_effects;
pub mod definitions;
pub mod dependencies;
pub mod evaluation_order;
pub mod expression_shapes;
pub mod fingerprints;
pub mod getter_queries;
pub mod getter_results;
pub mod globals;
pub mod identity_writes;
pub mod intrinsic_invocation;
pub mod iteration_sources;
pub mod limits;
pub mod map_operations;
pub mod member_mutations;
pub mod module_interop;
pub mod module_links;
pub mod mutation_initializers;
pub mod mutation_values;
pub mod object_references;
pub mod objects;
pub mod opaque_effects;
pub mod primitives;
pub mod projection;
pub mod promises;
pub mod property_paths;
pub mod provenance;
pub mod reference_role;
pub mod reference_sources;
pub mod require_origin;
pub mod resource_effects;
pub mod returned_references;
pub mod returns;
pub mod slots;
pub mod state;
pub mod symbolic_bindings;
pub mod symbolic_values;
pub mod value_types;
pub mod values;

#[cfg(test)]
mod tests;
