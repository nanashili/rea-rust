//! Enhanced native workflows and session comparisons built on the binary
//! session port (`rea_tools_binary::port`).
//!
//! Enhanced tools run every provider operation through
//! `with_admitted_analysis` and the admitted [`AnalysisPort`]; their
//! successful results become `rea-workflow` Evidence exactly as the original
//! composed workflows. Session tools derive Evidence from caller-supplied or
//! retained Evidence and record their sources, links and residual unknowns.
//!
//! [`AnalysisPort`]: rea_tools_binary::port::AnalysisPort
pub mod analysis;
pub mod derived;
pub mod domain;
pub mod enhanced;
pub mod js;
pub mod native;
pub mod session;
pub mod workflow;
pub mod zod;

use rea_mcp::Registry;

/// Bind every enhanced workflow tool to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    for name in enhanced::TOOLS {
        registry.handle(name, enhanced::execute);
    }
    registry.handle(
        "compare_functions",
        session::function_comparison::compare_functions,
    );
    registry.handle(
        "compare_artifacts",
        session::artifact_comparison::compare_artifacts,
    );
    registry.handle("build_call_path", session::call_path::build_call_path);
    registry.handle(
        "get_navigation_context",
        session::context::get_navigation_context,
    );
    registry.handle(
        "inspect_address_context",
        session::context::inspect_address_context,
    );
    registry.handle(
        "find_changed_behavior",
        session::changed_behavior::find_changed_behavior,
    );
    registry.handle(
        "correlate_static_and_runtime",
        session::static_runtime::correlate_static_and_runtime,
    );
    registry.handle(
        "verify_reconstruction",
        session::reconstruction::verify_reconstruction,
    );
}
