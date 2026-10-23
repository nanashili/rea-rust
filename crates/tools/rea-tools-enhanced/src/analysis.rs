//! Observed provider port for composed workflows.
//!
//! Compatibility owners: `executeComposedWorkflow` (`WorkflowEvidence.ts`),
//! `withProgressReporter` (`registerEnhancedTools.ts`), the `#call`/`#observe`
//! helpers of `EnhancedTools.ts` and `SourceLimitations.ts`.
//!
//! Every provider read of one composed call goes through [`Analysis`], which
//! records the limitations of exactly the successful observations it used and
//! forwards the request's progress sink to the provider.
use rea_analysis::{AnalysisExecution, ExecutionOptions, ProgressFn, ProviderIdentity};
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::cancellation::Cancellation;
use rea_mcp::Progress;
use rea_tools_binary::port::AnalysisPort;
use serde_json::{Map, Value};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Minimum interval between non-terminal progress notifications.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// One request's rate-bounded progress reporter (`createProgressReporter`).
#[derive(Clone)]
pub struct ProgressSink {
    progress: Progress,
    last_sent: Arc<Mutex<Option<Instant>>>,
}

impl ProgressSink {
    pub fn new(progress: Progress) -> Self {
        Self {
            progress,
            last_sent: Arc::new(Mutex::new(None)),
        }
    }

    /// Report one update; non-terminal updates within 100 ms are dropped.
    pub fn report(&self, phase: &str, message: &str, terminal: bool) {
        let now = Instant::now();
        {
            let mut last = self
                .last_sent
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !terminal && last.is_some_and(|sent| now.duration_since(sent) < PROGRESS_INTERVAL) {
                return;
            }
            *last = Some(now);
        }
        self.progress.report(phase, message);
    }

    /// The provider-facing progress callback sharing this sink's rate bound.
    pub fn provider_callback(&self) -> ProgressFn {
        let sink = self.clone();
        Arc::new(move |phase: &str, message: &str| sink.report(phase, message, false))
    }
}

/// One provider-owned caveat tied to the operation that reported it.
#[derive(Clone, Debug)]
struct SourceLimitation {
    provider: ProviderIdentity,
    operation: String,
    limitation: String,
}

/// `renderSourceLimitations`.
fn render_source_limitations(limitations: &[SourceLimitation]) -> Vec<String> {
    struct Group {
        provider: ProviderIdentity,
        limitation: String,
        operations: Vec<String>,
    }
    let mut groups: Vec<(String, Group)> = Vec::new();
    for fact in limitations {
        let key = serde_json::to_string(&serde_json::json!([
            fact.provider.id,
            fact.provider.name,
            fact.provider.version,
            fact.limitation,
        ]))
        .unwrap_or_default();
        match groups.iter_mut().find(|(existing, _)| *existing == key) {
            Some((_, group)) => {
                if !group.operations.contains(&fact.operation) {
                    group.operations.push(fact.operation.clone());
                }
            }
            None => groups.push((
                key,
                Group {
                    provider: fact.provider.clone(),
                    limitation: fact.limitation.clone(),
                    operations: vec![fact.operation.clone()],
                },
            )),
        }
    }
    let mut rendered = groups
        .into_iter()
        .map(|(_, group)| {
            let version = group
                .provider
                .version
                .as_ref()
                .map_or_else(String::new, |version| format!(" {version}"));
            let mut operations = group.operations;
            operations.sort();
            format!(
                "{} ({}{}) {}: {}",
                group.provider.name,
                group.provider.id,
                version,
                operations.join(", "),
                group.limitation
            )
        })
        .collect::<Vec<_>>();
    rendered.sort();
    rendered
}

/// Admitted provider port observed for one composed workflow.
pub struct Analysis<'a> {
    port: &'a dyn AnalysisPort,
    cancellation: Cancellation,
    progress: Option<ProgressFn>,
    limitations: RefCell<Vec<(String, SourceLimitation)>>,
}

impl<'a> Analysis<'a> {
    pub fn new(
        port: &'a dyn AnalysisPort,
        cancellation: Cancellation,
        progress: Option<ProgressFn>,
    ) -> Self {
        Self {
            port,
            cancellation,
            progress,
            limitations: RefCell::new(Vec::new()),
        }
    }

    /// The request's cancellation identity.
    pub fn cancellation(&self) -> &Cancellation {
        &self.cancellation
    }

    /// `signal?.aborted === true`.
    pub fn aborted(&self) -> bool {
        self.cancellation.reason().is_some()
    }

    /// `analysis.supportsOperation?.(operation) === true`.
    pub fn supports(&self, operation: &str) -> bool {
        self.port.supports_operation(operation)
    }

    /// Execute one provider operation (the composed port's `execute`).
    pub fn execute(
        &self,
        operation: &str,
        parameters: &Map<String, Value>,
        selector_from_provider: bool,
    ) -> Result<AnalysisExecution, AnalysisError> {
        let mut options = ExecutionOptions::new(self.cancellation.clone());
        options.progress = self.progress.clone();
        options.selector_from_provider = selector_from_provider;
        let execution = self.port.execute(operation, parameters, &options)?;
        let mut retained = self.limitations.borrow_mut();
        for limitation in &execution.limitations {
            let key = serde_json::to_string(&serde_json::json!([
                execution.provider.id,
                execution.provider.name,
                execution.provider.version,
                operation,
                limitation,
            ]))
            .unwrap_or_default();
            let fact = SourceLimitation {
                provider: execution.provider.clone(),
                operation: operation.to_owned(),
                limitation: limitation.clone(),
            };
            match retained.iter_mut().find(|(existing, _)| *existing == key) {
                Some((_, existing)) => *existing = fact,
                None => retained.push((key, fact)),
            }
        }
        drop(retained);
        Ok(execution)
    }

    /// `EnhancedTools.#observe`: cancellation before dispatch, and a completed
    /// observation retained when cancellation wins after it.
    pub fn observe(
        &self,
        operation: &str,
        parameters: &Map<String, Value>,
        selector_from_provider: bool,
    ) -> Result<AnalysisExecution, AnalysisError> {
        if self.aborted() {
            return Err(AnalysisError::cancelled(operation));
        }
        let execution = self.execute(operation, parameters, selector_from_provider)?;
        if self.aborted() {
            let cancelled = AnalysisError::cancelled(operation);
            return Err(
                match execution.evidence(operation, Value::Object(parameters.clone()), "observed") {
                    Ok(evidence) => cancelled.retain_partial_observation(evidence.into_value()),
                    Err(error) => error,
                },
            );
        }
        Ok(execution)
    }

    /// `EnhancedTools.#call`: the observed normalized result.
    pub fn call(
        &self,
        operation: &str,
        parameters: &Map<String, Value>,
        selector_from_provider: bool,
    ) -> Result<Value, AnalysisError> {
        self.observe(operation, parameters, selector_from_provider)
            .map(|execution| execution.result)
    }

    /// Rendered source limitations of every successful observation so far.
    pub fn source_limitations(&self) -> Vec<String> {
        let retained = self.limitations.borrow();
        let facts = retained
            .iter()
            .map(|(_, fact)| fact.clone())
            .collect::<Vec<_>>();
        render_source_limitations(&facts)
    }
}

/// Parameter map builder.
pub fn params(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Map<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

/// `error instanceof AnalysisCapabilityUnavailableError`.
pub fn is_capability_unavailable(error: &AnalysisError) -> bool {
    matches!(error.kind, ErrorKind::CapabilityUnavailable { .. })
}

/// `error._tag === "AnalysisCancelledError"`.
pub fn is_cancellation(error: &AnalysisError) -> bool {
    matches!(error.kind, ErrorKind::Cancelled { .. })
}
