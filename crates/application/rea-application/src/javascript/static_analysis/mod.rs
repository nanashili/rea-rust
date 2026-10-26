//! Static-analysis packages that read syntax plus a narrow set of semantic
//! answers (port plan H1/H2 and the AST parts of the static helpers):
//!
//! - [`fingerprint`] ports `javascriptAstFingerprint` (`babel-ast-v3` tokens).
//! - [`helpers`] ports `javascriptStaticAnalysisHelpers`.
//! - [`findings`] ports `javascriptStaticAnalysisFindings`.
//! - [`bootstrap`], [`bootstrap_integrity`] port `javascriptBootstrap*`.
//! - [`graphql`] ports `javascriptGraphqlOperations`.
//! - [`bundler`] ports `javascriptStaticAnalysisBundler`.
//! - [`interop`] ports the Rolldown template matcher of `javascriptModuleInterop`
//!   (`TO_ESM`/`COPY_PROPS`, `canonicalRoles`, `identityFunction`). The
//!   D2-dependent portions remain explicitly limited rather than inferred.
//!
//! Semantic answers (binding identity, stable initializers, parents,
//! references) come only through [`StaticSemantics`]. The semantic core
//! (`javascript::semantic`, another package) is their owner; these modules
//! never reinterpret scopes. Production analysis supplies the trait from the
//! in-process semantic state; the differential harness in
//! `.cache/rust-migration/js-static-diff/` is verification-only and must not be
//! treated as a runtime dependency or a parity claim.
pub mod analyze;
pub mod babel;
pub mod bootstrap;
pub mod bootstrap_integrity;
pub mod bundler;
pub mod bundler_calls;
pub mod calls;
pub mod electron_browser;
pub mod electron_context_bridge;
pub mod electron_ipc;
pub mod electron_native;
pub mod electron_options;
pub mod electron_paths;
pub mod electron_sender;
pub mod electron_values;
pub mod finalize;
pub mod findings;
pub mod fingerprint;
pub mod graphql;
pub mod helpers;
pub mod interop;
pub mod rpc;
pub mod semantics;
pub mod state;
mod symbolic_reads;
pub mod web;

pub use semantics::{BindingFacts, SemanticReference, StableInitializer, StaticSemantics};

#[cfg(test)]
mod tests;
