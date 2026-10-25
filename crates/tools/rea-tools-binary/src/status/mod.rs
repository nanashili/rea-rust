//! Target-independent projections used by the `binary_session` tool:
//! provider capability sets, the capability inventory / compact tool
//! availability, the production availability policy, negotiated client
//! features, and the server identity with catalog digests.
//!
//! Ported from the TypeScript runtime (`src/`), the oracle for this crate.
//! The orchestrator wires this module into `rea-tools-binary`.

mod availability_policy;
mod capability_sets;
mod catalog_digests;
mod client_features;
mod inventory;
mod server_identity;
pub use server_identity::PACKAGE_VERSION;

pub(crate) use availability_policy::production_availability_policy;
pub(crate) use capability_sets::provider_capability_sets;
pub(crate) use client_features::ClientFeatures;
pub(crate) use inventory::tool_availability;
pub(crate) use server_identity::{ServerIdentityInput, server_identity};
