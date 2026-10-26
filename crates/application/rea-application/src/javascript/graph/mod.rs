//! JavaScript Application Graph and Semantic Relation Graph construction.
//!
//! Ports the parent-side graph build of `analyze_javascript_application`
//! (`JavaScriptArtifactGraph*`, `JavaScriptModuleRelationships`,
//! `ElectronBoundaryGraph*`, `JavaScriptSemanticGraph*`,
//! `JavaScriptApplicationEvidenceGraph`) and the domain graph factories
//! (`javascriptApplicationGraph`, `javascriptSemanticGraph`).
//!
//! Inputs are the JSON facts the TypeScript analysis stages produce; outputs
//! are canonical-JSON identical to the TypeScript graphs, identifiers and
//! digests included. Module resolution is consumed through
//! [`resolution::ArtifactPathResolver`]; this module never reinterprets
//! declared paths. Not bound to any tool.

pub mod application_graph;
pub mod builder;
mod bundlers;
pub mod context;
pub(crate) mod direct_serializer;
mod documents;
pub mod electron;
pub mod evidence;
mod findings;
pub mod json;
pub mod leaves;
mod modules;
pub mod resolution;
pub mod semantic_builder;
pub mod semantic_graph;
pub(crate) mod semantic_ir_view;
mod semantic_lookup;
mod semantic_projection;
mod structure;

#[cfg(test)]
mod golden_tests;

pub use builder::{ApplicationGraphError, build_application_graph};
pub use semantic_builder::{
    SemanticGraphProjection, SemanticLimits, SemanticProjectionError, project_file,
};
