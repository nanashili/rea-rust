//! Named tool handlers bound to exact catalog contracts.
use super::catalog::{ToolContract, catalog};
use super::session::Session;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::Evidence;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Progress notification sink bound to one request's progress token.
#[derive(Clone)]
pub struct Progress {
    notify: Option<Arc<dyn Fn(u64, String) + Send + Sync>>,
    sequence: Arc<std::sync::atomic::AtomicU64>,
}

impl Progress {
    /// A sink that reports nothing (no progress token supplied).
    pub fn silent() -> Self {
        Self {
            notify: None,
            sequence: Arc::default(),
        }
    }

    pub fn new(notify: Arc<dyn Fn(u64, String) + Send + Sync>) -> Self {
        Self {
            notify: Some(notify),
            sequence: Arc::default(),
        }
    }

    /// Report `phase: message`; progress counts emitted observations.
    pub fn report(&self, phase: &str, message: &str) {
        if let Some(notify) = &self.notify {
            let sequence = self
                .sequence
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            notify(sequence, format!("{phase}: {message}"));
        }
    }
}

/// Everything a handler may use for one call.
pub struct ToolContext<'a> {
    pub contract: &'static ToolContract,
    pub session: &'a Arc<Session>,
    pub cancellation: Cancellation,
    pub progress: Progress,
}

impl ToolContext<'_> {
    pub fn name(&self) -> &str {
        &self.contract.name
    }

    /// The tool name with the catalog's static lifetime.
    pub fn name_static(&self) -> &'static str {
        self.contract.name.as_str()
    }

    /// Fail fast when the caller cancelled.
    pub fn check_cancelled(&self) -> Result<(), AnalysisError> {
        if self.cancellation.reason().is_some() {
            Err(AnalysisError::cancelled(self.contract.name.clone()))
        } else {
            Ok(())
        }
    }
}

/// Result of one handler invocation.
pub enum ToolOutput {
    /// Retained and delivered as Evidence.
    Evidence(Evidence),
    /// Delivered as a plain value (`{ result }` for session tools).
    Value(Value),
    /// A typed failure; a partial Evidence observation is retained first.
    Failure(AnalysisError),
    /// A pre-built MCP CallToolResult (used for exact legacy projections).
    Raw(Value),
}

impl From<Result<Evidence, AnalysisError>> for ToolOutput {
    fn from(result: Result<Evidence, AnalysisError>) -> Self {
        match result {
            Ok(evidence) => Self::Evidence(evidence),
            Err(error) => Self::Failure(error),
        }
    }
}

impl From<AnalysisError> for ToolOutput {
    fn from(error: AnalysisError) -> Self {
        Self::Failure(error)
    }
}

/// One named handler. Calls run on a dedicated worker thread.
pub trait ToolHandler: Send + Sync {
    fn call(&self, context: &ToolContext<'_>, input: Value) -> ToolOutput;
}

impl<F> ToolHandler for F
where
    F: Fn(&ToolContext<'_>, Value) -> ToolOutput + Send + Sync,
{
    fn call(&self, context: &ToolContext<'_>, input: Value) -> ToolOutput {
        self(context, input)
    }
}

/// Exact-name handler registry.
#[derive(Default)]
pub struct Registry {
    handlers: HashMap<String, Arc<dyn ToolHandler>>,
}

impl Registry {
    /// Bind a handler to an existing catalog contract.
    ///
    /// # Panics
    /// Binding an uncatalogued name is a programming error.
    pub fn register(&mut self, name: &str, handler: impl ToolHandler + 'static) {
        assert!(
            catalog().tool(name).is_some(),
            "tool {name} is not in the frozen catalog"
        );
        self.handlers.insert(name.to_owned(), Arc::new(handler));
    }

    /// Register one closure handler.
    pub fn handle<F>(&mut self, name: &str, handler: F)
    where
        F: Fn(&ToolContext<'_>, Value) -> ToolOutput + Send + Sync + 'static,
    {
        self.register(name, handler);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn ToolHandler>> {
        self.handlers.get(name).cloned()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }

    /// Catalog tools without a bound handler (reported as unavailable).
    pub fn unbound(&self) -> Vec<&'static str> {
        catalog()
            .tools
            .iter()
            .filter(|tool| !self.handlers.contains_key(&tool.name))
            .map(|tool| tool.name.as_str())
            .collect()
    }
}
