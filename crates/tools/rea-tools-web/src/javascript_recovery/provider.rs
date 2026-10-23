//! Serialized recovery adapter resolving an external engine, then publishing.
//!
//! Compatibility owner: `src/javascript/recovery/WakaruProvider.ts`.
//!
//! The provider resolves and fingerprints the configured command first. On any
//! host where Wakaru is not an absolute Linux/x64 command, that resolution
//! returns the typed capability-unavailable error and nothing else runs. The
//! Linux execution and publication pipeline lives in `execution`.

use std::sync::{Arc, Mutex};

use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_mcp::{Session, SessionResource, ToolContext};
use serde_json::Value;

use crate::javascript_recovery::command::resolve_wakaru_command;
use crate::javascript_recovery::execution::prepare_wakaru_execution;
use crate::javascript_recovery::{OPERATION, ParsedInput};

/// One completed provider observation with exact producing provenance.
pub(crate) struct Execution {
    pub result: Value,
    pub raw_result: Value,
    pub provider_id: String,
    pub provider_version: String,
    pub limitations: Vec<String>,
    pub locations: Vec<Value>,
    pub subject: SubjectTarget,
}

impl Execution {
    /// Rebind the execution to its immutable input, exactly as the TS service
    /// does before emitting Evidence.
    pub fn into_evidence(self, parsed: &ParsedInput) -> Result<Evidence, AnalysisError> {
        // Identity agreement checks mirror `JavaScriptRecoveryService.recover`.
        let source_path = self.result["source"]["path"].as_str().unwrap_or_default();
        let source_sha = self.result["source"]["sha256"].as_str().unwrap_or_default();
        let additional = self.result["additional_sources"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let engine_id = self.result["engine"]["id"].as_str().unwrap_or_default();
        let engine_version = self.result["engine"]["version"]
            .as_str()
            .unwrap_or_default();

        let additional_matches = additional.len() == parsed.additional_paths.len()
            && parsed
                .additional_paths
                .iter()
                .enumerate()
                .all(|(index, path)| {
                    additional
                        .get(index)
                        .and_then(|source| source["path"].as_str())
                        == Some(path.as_str())
                });

        if source_path != parsed.path
            || !additional_matches
            || self.subject.path != source_path
            || self.subject.sha256 != source_sha
            || self.provider_id != engine_id
            || self.provider_version != engine_version
        {
            return Err(AnalysisError::output(
                OPERATION,
                "Recovery source or engine identity disagrees with its Evidence binding",
            ));
        }

        let provider = EvidenceProvider::new(
            self.provider_id.clone(),
            crate::javascript_recovery::release::WAKARU_PROVIDER_NAME,
            Some(self.provider_version.clone()),
        );
        let observation = Observation::new(OPERATION, parsed.raw.clone(), self.result)
            .raw(self.raw_result)
            .locations(self.locations)
            .limitations(self.limitations)
            .confidence("derived")
            .authority("shipped-artifact");

        Evidence::create(Some(&self.subject), &provider, observation).map_err(|cause| {
            AnalysisError::output(
                OPERATION,
                format!("Evidence canonicalization failed: {cause}"),
            )
        })
    }
}

/// Session-owned provider. One recovery runs at a time per connection.
#[derive(Default)]
pub(crate) struct WakaruProvider {
    lock: Mutex<()>,
}

impl SessionResource for WakaruProvider {
    fn close(&self) -> Result<(), AnalysisError> {
        Ok(())
    }
}

impl WakaruProvider {
    /// Resolve the engine and, on Linux, run and publish the recovery.
    pub fn recover(
        &self,
        context: &ToolContext<'_>,
        parsed: &ParsedInput,
    ) -> Result<Execution, AnalysisError> {
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let session: &Session = context.session;
        // `resolveWakaruCommand`: capability-unavailable on any non-Linux host
        // or without an absolute configured command. This is the reachable
        // path on this macOS host.
        let engine = resolve_wakaru_command(session)?;
        prepare_wakaru_execution(context, parsed, &engine)
    }
}

/// Acquire the session-owned provider, registering its shutdown hook once.
pub(crate) fn provider(context: &ToolContext<'_>) -> Arc<WakaruProvider> {
    let state = context.session.state::<WakaruProvider>();
    context.session.own_once::<WakaruProvider>(state.clone());
    state
}
