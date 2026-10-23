//! The Rust Ghidra provider candidate; availability inspection never
//! launches the worker.
//!
//! Compatibility owners: `src/ghidra-rust/GhidraRustProvider.ts` and the
//! unavailable fallback of `src/composition/localGhidraRustProvider.ts`.
use crate::client::Client;
use crate::configuration::{Configuration, Inspection, inspect, worker_environment};
use crate::identity::{PROVIDER_ID, capabilities, identity, target_support};
use crate::profile::{fingerprint, profile_for};
use rea_analysis::{
    AnalysisClient, AnalysisProvider, BinaryTarget, CapabilityDescriptor, ProviderAvailability,
    ProviderIdentity, TargetSupport,
};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::path::PathBuf;

/// Explicit local worker candidate bound to one environment snapshot.
pub struct GhidraRustProvider {
    environment: HashMap<String, String>,
    current_executable: Option<PathBuf>,
}

impl GhidraRustProvider {
    /// Bind the provider to the session environment snapshot and the path of
    /// the running `rea` executable (used to locate the bundled worker).
    pub fn new(environment: HashMap<String, String>, current_executable: Option<PathBuf>) -> Self {
        Self {
            environment,
            current_executable,
        }
    }

    fn inspection(&self) -> Inspection {
        inspect(&self.environment, self.current_executable.as_deref())
    }

    fn configuration(&self, operation: &str) -> Result<Configuration, AnalysisError> {
        match self.inspection() {
            Inspection::Available { configuration, .. } => Ok(configuration),
            Inspection::Unavailable { code, reason, .. } => {
                Err(unavailable_error(operation, code, &reason))
            }
        }
    }
}

/// `unavailableProviderRemediation` for the native-runtime configuration.
fn remediation(code: &str) -> &'static str {
    match code {
        "not_configured" => {
            "Configure the Rust worker: build rea-ghidra-rust-worker beside rea or set REA_GHIDRA_RUST_WORKER, and leave REA_GHIDRA_RUST_ENABLED unset or set it to true."
        }
        "executable_missing" => {
            "Build the Rust worker with `npm run build:ghidra:rust-worker`, then place it beside rea or set REA_GHIDRA_RUST_WORKER to its absolute path."
        }
        "unsupported_host" => "Run REA on macOS or Linux to use the Rust worker.",
        _ => "Inspect the provider configuration, then retry.",
    }
}

fn unavailable_error(operation: &str, code: &str, reason: &str) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("failure_kind".into(), json!(code));
    diagnostics.insert("worker_started".into(), json!(false));
    AnalysisError::provider_adapter(PROVIDER_ID, operation)
        .with_user_message(reason)
        .with_remediation(remediation(code))
        .with_diagnostics(diagnostics)
}

impl AnalysisProvider for GhidraRustProvider {
    fn identity(&self) -> ProviderIdentity {
        identity()
    }

    fn capabilities(&self) -> Vec<CapabilityDescriptor> {
        capabilities(self.inspection().reason())
    }

    fn inspect_availability(&self, _cancellation: &Cancellation) -> ProviderAvailability {
        match self.inspection() {
            Inspection::Available { diagnostics, .. } => {
                ProviderAvailability::Available { diagnostics }
            }
            Inspection::Unavailable {
                code,
                reason,
                diagnostics,
            } => ProviderAvailability::Unavailable {
                code: code.to_owned(),
                reason,
                diagnostics,
            },
        }
    }

    fn inspect_target_support(&self, target: &BinaryTarget) -> TargetSupport {
        target_support(target)
    }

    fn resolve_analysis_profile(
        &self,
        target: &BinaryTarget,
        cancellation: &Cancellation,
    ) -> Result<Option<Value>, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("profile"));
        }
        if let TargetSupport::Unsupported { reason, .. } = target_support(target) {
            return Err(AnalysisError::unsupported_target(
                "profile",
                &target.path,
                reason,
            ));
        }
        let configuration = self.configuration("profile")?;
        let fingerprint = fingerprint(&configuration.command, cancellation)?;
        profile_for(&configuration, target, &fingerprint).map(Some)
    }

    fn create_client(
        &self,
        target: &BinaryTarget,
        profile: Option<&Value>,
        run_id: &str,
    ) -> Result<Box<dyn AnalysisClient>, AnalysisError> {
        let configuration = self.configuration("create_analysis_client")?;
        let environment = worker_environment(&self.environment, &configuration);
        Ok(Box::new(Client::new(
            target.clone(),
            configuration,
            environment,
            profile.cloned(),
            run_id,
        )))
    }
}
