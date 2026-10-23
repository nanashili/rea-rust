//! Shared Cutter bridge workflows (`CutterBridgeService`).
//!
//! Owns the single `Client`, the pending-cleanup bookkeeping for `unknown`
//! commands, and the Evidence construction. Registered into the MCP session as
//! a `SessionResource` so shutdown drives `close()` (descriptor cleanup retry
//! plus any pending-completion recovery), matching the provider close set in
//! `createServer.ts`.

use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{SessionResource, ToolContext, ToolOutput};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::client::{Client, ExecuteInput, ExecutionState, PROVIDER_ID, PROVIDER_NAME};

/// One retained pending-cleanup entry (`CutterBridgeService.#pendingCleanup`).
struct Pending {
    session_id: String,
    completion_token: Option<String>,
    /// The `AnalysisOutputError` whose cleanup is resolved once a terminal
    /// receipt confirms completion.
    failure: AnalysisError,
}

/// Per-MCP-session Cutter bridge state. Created on first use via
/// `context.session.state::<CutterBridgeState>()`.
pub(crate) struct CutterBridgeState {
    inner: Mutex<Option<Arc<Client>>>,
    pending_cleanup: Mutex<HashMap<String, Pending>>,
}

impl Default for CutterBridgeState {
    fn default() -> Self {
        Self {
            inner: Mutex::new(None),
            pending_cleanup: Mutex::new(HashMap::new()),
        }
    }
}

impl CutterBridgeState {
    fn client(&self, context: &ToolContext<'_>) -> Arc<Client> {
        let mut guard = self.inner.lock().unwrap();
        guard
            .get_or_insert_with(|| Arc::new(Client::new(context.session.environment())))
            .clone()
    }

    /// `CutterBridgeService.retryCleanup` + `#retryPendingCleanup`: release
    /// timed-out work only after producer-owned terminal proof.
    fn retry_cleanup(&self, client: &Client) -> Result<(), AnalysisError> {
        let mut pending = self.pending_cleanup.lock().unwrap();
        let request_ids: Vec<String> = pending.keys().cloned().collect();
        for request_id in request_ids {
            let (session_id, completion_token) = {
                let entry = pending.get(&request_id).expect("key enumerated above");
                (entry.session_id.clone(), entry.completion_token.clone())
            };
            match client.confirm_command_completion(
                &session_id,
                &request_id,
                completion_token.as_deref(),
            ) {
                Ok(true) => {
                    pending.remove(&request_id);
                }
                Ok(false) => {
                    return Err(pending
                        .get(&request_id)
                        .expect("entry retained on unconfirmed cleanup")
                        .failure
                        .clone());
                }
                Err(_) => {
                    return Err(pending
                        .get(&request_id)
                        .expect("entry retained on confirmation error")
                        .failure
                        .clone());
                }
            }
        }
        Ok(())
    }

    /// `CutterBridgeService.listSessions`.
    pub(crate) fn list_sessions(
        &self,
        context: &ToolContext<'_>,
    ) -> Result<serde_json::Value, AnalysisError> {
        let client = self.client(context);
        if context.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("list_cutter_sessions"));
        }
        let discovery = client.list_sessions(&context.cancellation)?;
        if context.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("list_cutter_sessions"));
        }
        let sessions: Vec<serde_json::Value> = discovery
            .sessions
            .iter()
            .map(|session| {
                serde_json::json!({
                    "session_id": session.session_id,
                    "pid": session.pid,
                    "document_generation": session.document_generation,
                    "current_file": session.current_file,
                    "cutter_version": session.cutter_version,
                    "identity_status": "partial",
                })
            })
            .collect();
        Ok(serde_json::json!({
            "sessions": sessions,
            "bridge_directory": discovery.bridge_directory,
            "discovery_status": discovery.discovery_status,
            "bridge_directory_security": discovery.bridge_directory_security,
        }))
    }

    /// `CutterBridgeService.execute`, including the external-mutation admission
    /// path. The admission hook is owned by `rea-tools-binary` and is
    /// unreachable here, so this takes the TS path for an `undefined` hook:
    /// run cleanup recovery first, then execute directly.
    pub(crate) fn execute(
        &self,
        context: &ToolContext<'_>,
        input: serde_json::Value,
    ) -> ToolOutput {
        let client = self.client(context);

        // `runWithExternalMutationAdmission` with an undefined session: run
        // cleanupRecovery, propagate its failure, then the operation.
        if let Err(error) = self.retry_cleanup(&client) {
            return ToolOutput::Failure(error);
        }
        match self.execute_once(&client, context, input) {
            Ok(evidence) => ToolOutput::Evidence(evidence),
            Err(error) => ToolOutput::Failure(error),
        }
    }

    fn execute_once(
        &self,
        client: &Client,
        context: &ToolContext<'_>,
        input: serde_json::Value,
    ) -> Result<Evidence, AnalysisError> {
        // The framework already validated `input` against the frozen
        // inputSchema (uuid session_id, non-negative generation, non-empty
        // single-line command, boolean json default false). Re-parse the
        // typed fields.
        let parsed = parse_input(&input)?;

        if context.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("cutter_command"));
        }

        let execution = client.execute(&parsed, &context.cancellation)?;

        let normalized_output = execution.output.clone();
        let evidence = build_evidence(&parsed, &execution, &normalized_output)?;

        if execution.execution_state == ExecutionState::Unknown {
            let failure = AnalysisError::output(
                "cutter_command",
                "Cutter command completion is unknown; the bound binary remains unavailable until the UI dispatcher confirms this request reached a terminal state.",
            )
            .with_cleanup(
                "The exact UI dispatcher completion receipt has not arrived; the dispatched command may still be running.",
                vec![format!("cutter-session:{}", parsed.session_id)],
            )
            .retain_partial_observation(evidence.value().clone());

            let mut pending = self.pending_cleanup.lock().unwrap();
            pending.insert(
                execution.request_id.clone(),
                Pending {
                    session_id: parsed.session_id.clone(),
                    completion_token: execution.completion_token.clone(),
                    failure: failure.clone(),
                },
            );
            return Err(failure);
        }

        if context.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("cutter_command")
                .retain_partial_observation(evidence.into_value()));
        }
        Ok(evidence)
    }

    /// `CutterBridgeService.close`: confirm pending cleanup, then retry
    /// descriptor cleanup. Returns `Err` to keep ownership for a later retry.
    fn close(&self) -> Result<(), AnalysisError> {
        let client = {
            let guard = self.inner.lock().unwrap();
            guard.clone()
        };
        let Some(client) = client else {
            return Ok(());
        };
        // Pending cleanup confirmation first (the `retryCleanup` in `close`).
        self.retry_cleanup(&client)?;
        Ok(())
    }
}

/// `SessionResource` wrapper so a shutdown drives `close()`.
pub(crate) struct CutterServiceResource(pub(crate) Arc<CutterBridgeState>);

impl SessionResource for CutterServiceResource {
    fn close(&self) -> Result<(), AnalysisError> {
        self.0.close()
    }
}

/// Build the `cutter_command` Evidence exactly as `CutterBridgeService.execute`
/// does: provider identity with the observed Cutter version, the
/// command-observation predicate, the caller parameters, the normalized
/// result, the raw result, the subject-unavailable reason, and the
/// state-dependent limitations.
fn build_evidence(
    input: &ExecuteInput,
    execution: &super::client::Execution,
    normalized_output: &serde_json::Value,
) -> Result<Evidence, AnalysisError> {
    let provider =
        EvidenceProvider::new(PROVIDER_ID, PROVIDER_NAME, execution.cutter_version.clone());

    let parameters = serde_json::json!({
        "session_id": input.session_id,
        "expected_generation": input.expected_generation,
        "command": input.command,
        "json": input.json,
    });
    let result = serde_json::json!({
        "command": input.command,
        "output": normalized_output,
        "execution_state": execution.execution_state.as_str(),
        "error": execution.error,
        "message": execution.message,
        "output_truncated": execution.output_truncated,
        "cutter_version": execution.cutter_version,
        "current_file": execution.current_file,
        "document_generation": execution.document_generation,
        "identity_status": "partial",
    });

    let mut limitations = vec![
        "Document identity is partial: the bridge uses a plugin instance UUID and observed generation; a same-path tab switch or reload may not be distinguishable.".to_owned(),
        "Cutter command effects depend on the Rizin command and active plugins.".to_owned(),
        "The local IPC protocol is implemented by REA and is not an upstream Cutter API.".to_owned(),
    ];
    if execution.execution_state == ExecutionState::Unknown {
        limitations.push(
            "Command completion or its output could not be confirmed; do not retry automatically because the command may have produced partial or persistent effects.".to_owned(),
        );
    }
    if execution.output_truncated {
        limitations.push(
            "The command completed or may have completed, but output exceeded the bridge transport limit and was omitted.".to_owned(),
        );
    }

    let observation = Observation::new("cutter_command", parameters, result)
        .predicate("rea.cutter.command-observation")
        .raw(normalized_output.clone())
        .subject_unavailable(
            "Cutter exposes no verified stable identity for the active unsaved document or tab.",
        )
        .limitations(limitations);

    Evidence::create(None, &provider, observation)
        .map_err(|error| AnalysisError::output("cutter_command", error.to_string()))
}

fn parse_input(input: &serde_json::Value) -> Result<ExecuteInput, AnalysisError> {
    let object = input
        .as_object()
        .ok_or_else(|| AnalysisError::input("cutter_command", Vec::new()))?;
    let session_id = object
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AnalysisError::input("cutter_command", Vec::new()))?
        .to_owned();
    let expected_generation = object
        .get("expected_generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| AnalysisError::input("cutter_command", Vec::new()))?;
    let command = object
        .get("command")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AnalysisError::input("cutter_command", Vec::new()))?
        .to_owned();
    let json = object
        .get("json")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Ok(ExecuteInput {
        session_id,
        expected_generation,
        command,
        json,
    })
}
