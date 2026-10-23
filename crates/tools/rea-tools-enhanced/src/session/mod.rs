//! Evidence-composed session comparisons and investigations.
//!
//! Compatibility owners: `registerFunctionComparisonTool.ts`,
//! `registerArtifactComparisonTool.ts` and `registerInvestigationTools.ts`.
pub mod artifact_comparison;
pub mod call_path;
pub mod changed_behavior;
pub mod context;
pub mod function_comparison;
pub mod investigation;
pub mod reconstruction;
pub mod static_runtime;
