//! Binary analysis session: provider selection, snapshots, official tools and
//! session navigation.
//!
//! `port` is the stable API other families (enhanced workflows, CLI) use to run
//! provider operations against the admitted active target.
use rea_analysis::AnalysisProvider;
use rea_mcp::{CompletionProvider, NoCompletion, Registry, Session};
use std::sync::Arc;

mod errors;
mod lifecycle;
mod official;
pub mod port;
mod refine;
mod router;
mod session;
mod snapshot;
mod status;
pub use status::PACKAGE_VERSION;
mod target;

/// The configured deep-analysis providers shared by every binary tool.
pub(crate) struct Registration {
    providers: Vec<Arc<dyn AnalysisProvider>>,
}

impl Registration {
    /// The session's binary state with its provider router bound (the first
    /// binding wins; the default selector comes from the session snapshot).
    pub(crate) fn bind(&self, session: &Arc<Session>) -> Arc<session::BinarySession> {
        session::bind(session, || {
            router::Router::new(self.providers.clone(), session.env("REA_ANALYSIS_PROVIDER"))
        })
    }
}

/// Bind every binary-session tool; `providers` are the configured deep
/// analysis providers in deterministic registry order.
///
/// The provider router is bound to `session` immediately so composed
/// workflows that only use the port observe the same candidates.
pub fn register(
    registry: &mut Registry,
    session: &Arc<Session>,
    providers: Vec<Arc<dyn AnalysisProvider>>,
) {
    let registration = Arc::new(Registration { providers });
    registration.bind(session);
    lifecycle::register(registry, &registration);
    official::register(registry, &registration);
}

/// Live document, procedure and provider completion for guided prompts.
pub fn completion(_session: &Arc<Session>) -> Arc<dyn CompletionProvider> {
    Arc::new(NoCompletion)
}
