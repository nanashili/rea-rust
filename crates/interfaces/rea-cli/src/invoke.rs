//! Thin wrapper over `rea_mcp::invoke` binding the session, registry and
//! shared cancellation for one CLI process.
use rea_core::cancellation::Cancellation;
use rea_mcp::{Progress, Registry, Session};
use serde_json::{Value, value::RawValue};
use std::sync::Arc;

pub use rea_mcp::Invocation;

/// Everything one in-process tool call needs.
pub struct Runner<'a> {
    pub registry: &'a Registry,
    pub session: &'a Arc<Session>,
    pub cancellation: Cancellation,
}

impl Runner<'_> {
    /// Run one catalog tool by name with the shared validation and Evidence
    /// retention, returning its success value or failure projection.
    pub fn invoke(&self, name: &str, input: Value) -> Invocation {
        rea_mcp::invoke(
            self.registry,
            self.session,
            name,
            input,
            self.cancellation.clone(),
            Progress::silent(),
        )
    }

    /// Run a tool with its original JSON text when the registry exposes an
    /// exact-input handler; ordinary tools retain the decoded fallback path.
    pub fn invoke_raw(&self, name: &str, input: Box<RawValue>) -> Invocation {
        rea_mcp::invoke_raw(
            self.registry,
            self.session,
            name,
            input,
            self.cancellation.clone(),
            Progress::silent(),
        )
    }
}
