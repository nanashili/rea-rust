//! JEB-backed inspection served by a caller-supplied running engine client.
//!
//! Compatibility owners: `src/server/registerJebTools.ts`,
//! `src/application/jeb/JebAnalysisService.ts`,
//! `src/application/ProviderOperationExecution.ts`, `src/jeb/JebProvider.ts`,
//! `src/jeb/JebMcpConnection.ts`, `src/jeb/JebMcpConnectionOwner.ts`,
//! `src/jeb/JebMcpEndpoint.ts`, `src/jeb/JebMcpDeadline.ts` and
//! `src/composition/jeb.ts`.
//!
//! JEB is reached as an MCP server over a loopback HTTP endpoint. REA never
//! launches the engine, reads the target file or executes it; the engine
//! resolves and analyzes the artifact on its own host. The connection is
//! retained in session state and torn down by a session resource.
mod endpoint;
mod http;
mod mcp;
mod provider;

use crate::common::evidence::{Execution, complete, execution_evidence};
use provider::{JebProvider, ProviderBuild, availability_unavailable, build_provider};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_mcp::{Registry, Session, SessionResource, ToolContext, ToolOutput};
use serde_json::Value;
use std::sync::{Arc, Mutex, OnceLock};

/// Bind JEB handlers to their exact named contracts.
pub fn register(registry: &mut Registry) {
    registry.handle("inspect_jeb_client", |context, input| {
        run(context, "inspect_jeb_client", input)
    });
    registry.handle("open_jeb_project", |context, input| {
        run(context, "open_jeb_project", input)
    });
    registry.handle("list_jeb_units", |context, input| {
        run(context, "list_jeb_units", input)
    });
    registry.handle("decompile_jeb_item", |context, input| {
        run(context, "decompile_jeb_item", input)
    });
}

/// Report JEB readiness without opening a project (`ProviderAvailability`).
///
/// Compatibility owner: `JebProvider.inspectAvailability`, used by the
/// binary-session owner to discover provider readiness and advertised
/// operations. An unusable endpoint or timeout reports `not_configured`.
pub fn availability(session: &Arc<Session>, cancellation: &Cancellation) -> Value {
    let state = session.state::<JebState>();
    match state.provider(session) {
        Ok(provider) => provider.availability(cancellation),
        Err(unconfigured) => availability_unavailable(&unconfigured.setting, &unconfigured.reason),
    }
}

/// Shared CLI/MCP admission, execution and Evidence composition for JEB.
///
/// Compatibility owner: `executeProviderOperation`. Input is already validated
/// against the frozen inputSchema with defaults applied; only cancellation,
/// provider dispatch and Evidence assembly remain.
fn run(context: &ToolContext<'_>, operation: &'static str, input: Value) -> ToolOutput {
    // decompile is a derived observation; the rest are observed.
    let confidence = if operation == "decompile_jeb_item" {
        "derived"
    } else {
        "observed"
    };

    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(operation));
    }

    let state = context.session.state::<JebState>();
    let provider = match state.provider(context.session) {
        Ok(provider) => provider,
        Err(unconfigured) => return ToolOutput::Failure(unconfigured.error.clone()),
    };

    let execution = match provider.execute(operation, &input, &context.cancellation) {
        Ok(execution) => execution,
        Err(error) => return ToolOutput::Failure(error),
    };

    match build_evidence(
        operation,
        &input,
        execution,
        confidence,
        &context.cancellation,
    ) {
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

/// `createAnalysisExecutionEvidence` then `completeProviderEvidence`.
fn build_evidence(
    operation: &str,
    input: &Value,
    execution: Execution,
    confidence: &str,
    cancellation: &Cancellation,
) -> Result<rea_core::evidence::envelope::Evidence, AnalysisError> {
    let parameters = input.clone();
    let evidence = execution_evidence(operation, parameters, execution, confidence)?;
    complete(evidence, cancellation, None)
}

/// Per-session JEB provider state and its connection ownership.
///
/// Compatibility owner: the composed `JebProvider` singleton plus the
/// connection-owner cleanup hook, here registered as a `SessionResource`.
#[derive(Default)]
struct JebState {
    provider: OnceLock<Result<Arc<JebProvider>, Arc<Unconfigured>>>,
    cleanup: Mutex<Option<Arc<ConnectionCleanup>>>,
}

/// The configuration failure for an unusable endpoint or timeout.
struct Unconfigured {
    setting: String,
    reason: String,
    error: AnalysisError,
}

impl JebState {
    /// Resolve the provider, building it once from the session environment.
    fn provider(&self, session: &Arc<Session>) -> Result<Arc<JebProvider>, Arc<Unconfigured>> {
        let resolved = self
            .provider
            .get_or_init(|| match build_provider(session.environment()) {
                ProviderBuild::Ready(provider) => Ok(Arc::new(provider)),
                ProviderBuild::Unconfigured {
                    setting,
                    reason,
                    error,
                } => Err(Arc::new(Unconfigured {
                    setting,
                    reason,
                    error,
                })),
            });

        if let Ok(provider) = resolved {
            // Register connection cleanup once a usable provider exists.
            let mut cleanup = self
                .cleanup
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if cleanup.is_none() {
                let resource = Arc::new(ConnectionCleanup {
                    provider: Arc::clone(provider),
                });
                *cleanup = Some(Arc::clone(&resource));
                drop(cleanup);
                session.own_once(resource);
            }
        }

        resolved.clone()
    }
}

/// Session resource that releases the JEB connection at shutdown.
///
/// Compatibility owner: `JebProvider.close` over `JebMcpConnectionOwner`. A
/// failed termination keeps ownership for a later retry (`close` returns Err).
struct ConnectionCleanup {
    provider: Arc<JebProvider>,
}

impl SessionResource for ConnectionCleanup {
    fn close(&self) -> Result<(), AnalysisError> {
        // Cleanup runs without a caller cancellation; a fresh identity is used.
        self.provider.close(&Cancellation::default())
    }
}
