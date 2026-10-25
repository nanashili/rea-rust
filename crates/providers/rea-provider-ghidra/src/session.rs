//! One lazily prepared target, one immutable inventory, and no replacement
//! worker.
//!
//! Compatibility owner: `src/ghidra-rust/GhidraRustSession.ts`.
use crate::configuration::Configuration;
use crate::identity::{PROVIDER_ID, identity, limitations};
use crate::profile::{profile_matches, worker_configuration_agrees};
use crate::protocol::{WorkerInfo, parse_info};
use crate::worker::{Control, Worker};
use rea_analysis::{AnalysisExecution, BinaryTarget};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex, MutexGuard};

const REQUIRED_COMMANDS: [&str; 18] = [
    "info",
    "open",
    "segments",
    "image_map",
    "search_bytes",
    "functions",
    "function_aliases",
    "resolve_functions",
    "batch_decompile",
    "batch_decompile_inventory",
    "strings",
    "references_to",
    "references_from",
    "instructions",
    "inspect_instruction",
    "read_bytes",
    "checkpoint",
    "close",
];

#[derive(Default)]
struct State {
    info: Option<Arc<WorkerInfo>>,
    /// The memoized preparation failure (`#preparation`).
    preparation: Option<AnalysisError>,
}

/// `GhidraRustSession`.
pub(crate) struct Session {
    pub worker: Arc<Worker>,
    target: BinaryTarget,
    configuration: Configuration,
    profile: Option<Value>,
    state: Mutex<State>,
}

impl Session {
    pub(crate) fn new(
        worker: Arc<Worker>,
        target: BinaryTarget,
        configuration: Configuration,
        profile: Option<Value>,
    ) -> Self {
        Self {
            worker,
            target,
            configuration,
            profile,
            state: Mutex::new(State::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn info(&self) -> Option<Arc<WorkerInfo>> {
        self.lock().info.clone()
    }

    pub(crate) fn timeout_ms(&self) -> u64 {
        self.configuration.timeout_ms
    }

    /// The prepared inventory commitment.
    pub(crate) fn inventory_sha256(&self) -> Option<String> {
        self.info().and_then(|info| info.inventory_sha256.clone())
    }

    /// `prepare`: open the target once per worker.
    pub(crate) fn prepare(&self, control: &Control) -> Result<Arc<WorkerInfo>, AnalysisError> {
        if let Some(failure) = self.worker.failure() {
            return Err(failure);
        }
        {
            let state = self.lock();
            if let Some(info) = &state.info {
                return Ok(Arc::clone(info));
            }
            if let Some(failure) = &state.preparation {
                return Err(failure.clone());
            }
        }
        let prepared = self.open(control);
        let mut state = self.lock();
        match &prepared {
            Ok(info) => state.info = Some(Arc::clone(info)),
            Err(failure) => state.preparation = Some(failure.clone()),
        }
        prepared
    }

    /// `observe`: re-read worker identity and prove the frozen inventory and
    /// configuration did not change.
    pub(crate) fn observe(&self, control: &Control) -> Result<WorkerInfo, AnalysisError> {
        let Some(previous) = self.info() else {
            return Err(self.failure("The Rust worker is not prepared."));
        };
        let reply = self.worker.request("info", json!({}), Some(control))?;
        let checked = self.validate_info(&reply, true)?;
        if checked.inventory_sha256 != previous.inventory_sha256
            || checked.total != previous.total
            || checked.config_identity != previous.config_identity
        {
            return Err(
                self.failure("The frozen inventory or configuration changed during this session.")
            );
        }
        Ok(checked)
    }

    /// `retainBatchObservation`: keep completed batch items as Evidence on
    /// the failure.
    pub(crate) fn retain_batch_observation(
        &self,
        failure: AnalysisError,
        selectors: &[String],
        result: Value,
    ) -> AnalysisError {
        let mut execution = AnalysisExecution::new(result, identity());
        execution.analysis_profile = self.profile.clone();
        execution.subject = Some(self.target.subject());
        let mut retained = limitations();
        if let Some(info) = self.info() {
            retained.extend(info.limitations.iter().cloned());
        }
        retained.push(
            "Only completed items returned by the worker are included; later selectors may not have been processed."
                .to_owned(),
        );
        execution.limitations = retained;
        match execution.evidence(
            "batch_decompile",
            json!({ "addresses": selectors }),
            "observed",
        ) {
            Ok(evidence) => failure.retain_partial_observation(evidence.into_value()),
            Err(_) => failure,
        }
    }

    /// `failure`: an inventory-protocol adapter failure.
    pub(crate) fn failure(&self, message: &str) -> AnalysisError {
        let mut diagnostics = Map::new();
        diagnostics.insert("failure_kind".into(), json!("protocol"));
        AnalysisError::provider_adapter(PROVIDER_ID, "worker:inventory")
            .with_user_message(message)
            .with_diagnostics(diagnostics)
    }

    /// `#open`.
    fn open(&self, control: &Control) -> Result<Arc<WorkerInfo>, AnalysisError> {
        if !profile_matches(self.profile.as_ref(), &self.configuration, &self.target) {
            return Err(
                self.failure("A matching committed worker profile is required before preparation.")
            );
        }
        self.worker.start(control)?;
        let identity = self.worker.request("info", json!({}), Some(control))?;
        let checked = self.validate_info(&identity, false)?;
        let reply = self.worker.request(
            "open",
            json!({ "path": self.target.path, "target_sha256": self.target.sha256 }),
            Some(control),
        )?;
        let prepared = self.validate_info(&reply, true)?;
        if prepared.config_identity != checked.config_identity {
            return Err(self.failure("Worker configuration changed while opening the target."));
        }
        self.worker.record_prepared_target();
        Ok(Arc::new(prepared))
    }

    /// `#validateInfo`.
    fn validate_info(&self, value: &Value, prepared: bool) -> Result<WorkerInfo, AnalysisError> {
        let info = parse_info(value)
            .map_err(|_| self.failure("Malformed Rust worker identity metadata."))?;
        let committed = self
            .profile
            .as_ref()
            .and_then(|profile| profile["parameters"]["worker_sha256"].as_str());
        if committed != Some(info.worker_sha256.as_str()) || !worker_configuration_agrees(&info) {
            return Err(self.failure(
                "The worker executable or embedded specifications differ from the committed profile.",
            ));
        }
        if info.timeout_ms != self.configuration.timeout_ms {
            return Err(self.failure("Worker resource settings differ from the committed profile."));
        }
        if !REQUIRED_COMMANDS.iter().all(|command| {
            info.capabilities
                .iter()
                .any(|capability| capability == command)
        }) {
            return Err(
                self.failure("The worker does not advertise the required protocol commands.")
            );
        }
        if info.inventory_frozen != prepared {
            return Err(
                self.failure("The worker reported an unexpected inventory preparation state.")
            );
        }
        if prepared && !self.matches_target_inventory(&info) {
            return Err(self.failure(
                "The prepared inventory is not bound to the requested target and complete count.",
            ));
        }
        Ok(info)
    }

    fn matches_target_inventory(&self, info: &WorkerInfo) -> bool {
        info.target_sha256.as_deref() == Some(self.target.sha256.as_str())
            && info.inventory_sha256.is_some()
            && info.total.is_some()
            && info.total == info.indexed_functions
            && info.preparation.is_some()
    }
}
