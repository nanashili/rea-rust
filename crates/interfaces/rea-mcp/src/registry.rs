//! Named tool handlers bound to exact catalog contracts.
use super::catalog::{ToolContract, catalog};
use super::session::Session;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::{envelope::Evidence, record::EvidenceRecord};
use serde_json::{Value, value::RawValue};
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

/// Selects the owner of public input validation for a named registration.
///
/// SDK-owned registrations are validated by the transport before dispatch.
/// Application-owned registrations receive the raw caller value so their
/// source service can apply Zod defaults, refinements, and tagged failures
/// before any effects occur.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputValidation {
    Sdk,
    Application,
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
    /// Retained and delivered from an exact raw Evidence record.
    ///
    /// This variant is for producers whose normalized result contains source
    /// strings that cannot be represented by Rust UTF-8. The protocol keeps
    /// the record raw through the JSON-RPC response.
    RawEvidence(EvidenceRecord),
    /// A failed analysis with an exact partial Evidence record retained.
    ///
    /// The error projection carries only the retained-record reference; the
    /// record itself stays raw in the session ledger and transport path.
    RawFailure {
        evidence: EvidenceRecord,
        error: AnalysisError,
    },
    /// Delivered as a plain value (`{ result }` for session tools).
    Value(Value),
    /// A typed failure; a partial Evidence observation is retained first.
    Failure(AnalysisError),
    /// A pre-built MCP CallToolResult (used for exact legacy projections).
    Raw(Value),
    /// A pre-built raw MCP CallToolResult. Its JSON text is preserved through
    /// the transport and is never decoded into `serde_json::Value`.
    RawJson(Box<RawValue>),
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

/// Handler for a tool whose caller input must remain raw JSON.
///
/// This is deliberately a separate capability. Most tools retain the SDK's
/// decoded `Value` path; exact-source tools opt in only when decoding would
/// lose JavaScript UTF-16 code units such as lone surrogates.
pub trait RawToolHandler: Send + Sync {
    fn call_raw(&self, context: &ToolContext<'_>, input: &RawValue) -> ToolOutput;
}

impl<F> RawToolHandler for F
where
    F: Fn(&ToolContext<'_>, &RawValue) -> ToolOutput + Send + Sync,
{
    fn call_raw(&self, context: &ToolContext<'_>, input: &RawValue) -> ToolOutput {
        self(context, input)
    }
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
    handlers: HashMap<String, RegisteredHandler>,
    raw_handlers: HashMap<String, Arc<dyn RawToolHandler>>,
}

struct RegisteredHandler {
    handler: Arc<dyn ToolHandler>,
    validation: InputValidation,
}

impl Registry {
    /// Bind a handler to an existing catalog contract.
    ///
    /// # Panics
    /// Binding an uncatalogued name is a programming error.
    pub fn register(&mut self, name: &str, handler: impl ToolHandler + 'static) {
        self.register_with_validation(name, handler, InputValidation::Sdk);
    }

    /// Bind a handler whose application service owns input validation.
    pub fn register_application_validated(
        &mut self,
        name: &str,
        handler: impl ToolHandler + 'static,
    ) {
        self.register_with_validation(name, handler, InputValidation::Application);
    }

    fn register_with_validation(
        &mut self,
        name: &str,
        handler: impl ToolHandler + 'static,
        validation: InputValidation,
    ) {
        assert!(
            catalog().tool(name).is_some(),
            "tool {name} is not in the frozen catalog"
        );
        self.handlers.insert(
            name.to_owned(),
            RegisteredHandler {
                handler: Arc::new(handler),
                validation,
            },
        );
    }

    /// Register one closure handler.
    pub fn handle<F>(&mut self, name: &str, handler: F)
    where
        F: Fn(&ToolContext<'_>, Value) -> ToolOutput + Send + Sync + 'static,
    {
        self.register(name, handler);
    }

    /// Register a closure whose application service owns input validation.
    pub fn handle_application_validated<F>(&mut self, name: &str, handler: F)
    where
        F: Fn(&ToolContext<'_>, Value) -> ToolOutput + Send + Sync + 'static,
    {
        self.register_application_validated(name, handler);
    }

    /// Bind an exact raw-input capability alongside the ordinary handler.
    ///
    /// The ordinary handler remains the decoded in-process path. The MCP
    /// transport and CLI select this capability only when they have preserved
    /// the original request bytes for the named operation.
    pub fn handle_raw_application_validated<F>(&mut self, name: &str, handler: F)
    where
        F: Fn(&ToolContext<'_>, &RawValue) -> ToolOutput + Send + Sync + 'static,
    {
        assert!(
            catalog().tool(name).is_some(),
            "tool {name} is not in the frozen catalog"
        );
        self.raw_handlers.insert(name.to_owned(), Arc::new(handler));
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn ToolHandler>> {
        self.handlers
            .get(name)
            .map(|registered| Arc::clone(&registered.handler))
    }

    pub fn get_raw(&self, name: &str) -> Option<Arc<dyn RawToolHandler>> {
        self.raw_handlers.get(name).map(Arc::clone)
    }

    pub fn validation(&self, name: &str) -> InputValidation {
        self.handlers
            .get(name)
            .map(|registered| registered.validation)
            .unwrap_or(InputValidation::Sdk)
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
