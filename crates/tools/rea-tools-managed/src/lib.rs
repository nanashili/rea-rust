//! Managed .NET static analysis, managed-code workflows and analysis views.
//!
//! Compatibility owners: `src/server/registerManagedTools.ts`,
//! `src/server/registerManagedWorkflowTools/**`,
//! `src/server/registerAnalysisViewTool.ts` and their application, domain
//! and `src/dotnet/**` owners.
use rea_mcp::Registry;
mod analysis_view;
mod common;
mod dotnet;
mod managed_tools;
mod target;
mod workflows;
/// Bind every tool owned by this family to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    analysis_view::register(registry);
    managed_tools::register(registry);
    workflows::register(registry);
}
