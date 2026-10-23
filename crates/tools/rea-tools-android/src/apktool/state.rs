//! Per-session Apktool provider state and its shutdown resource.
//!
//! Compatibility owner: the owned-resource and `close()` lifecycle of
//! `ApktoolProvider` in `src/apktool/ApktoolProvider.ts`. One session owns one
//! provider; calls serialize through a turnstile as the single TS provider
//! instance does. Failed command cleanup and failed workspace removal keep
//! ownership in session state and are retried before each call and on close.

use crate::common::errors::provider_cleanup;
use crate::common::process::RetainedChild;
use crate::common::turnstile::Turnstile;
use crate::common::workspace::PrivateRoot;
use rea_core::analysis_error::AnalysisError;
use rea_mcp::{Session, SessionResource};
use std::sync::{Arc, Mutex};

use super::provider::APKTOOL_PROVIDER_ID;

/// One decode workspace whose removal failed and must be retried.
pub struct PendingWorkspace {
    pub root: PrivateRoot,
    pub resource: String,
}

/// Session-scoped Apktool state.
#[derive(Default)]
pub struct ApktoolState {
    inner: Mutex<ApktoolStateInner>,
    /// Serializes every Apktool call on this session, as the single TS provider.
    pub turn: Turnstile,
}

#[derive(Default)]
struct ApktoolStateInner {
    retained_children: Vec<RetainedChild>,
    pending_workspaces: Vec<PendingWorkspace>,
    closing: bool,
}

impl ApktoolState {
    fn lock(&self) -> std::sync::MutexGuard<'_, ApktoolStateInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Whether admission is terminally stopped.
    pub fn is_closing(&self) -> bool {
        self.lock().closing
    }

    /// Retain a child whose owned cleanup could not be confirmed.
    pub fn retain_child(&self, child: RetainedChild) {
        self.lock().retained_children.push(child);
    }

    /// Retain a decode workspace whose removal failed.
    pub fn retain_workspace(&self, pending: PendingWorkspace) {
        self.lock().pending_workspaces.push(pending);
    }

    /// Retry retained process cleanup; returns still-unresolved resource labels.
    pub fn retry_retained_children(&self) -> Vec<String> {
        let mut inner = self.lock();
        let mut retained = Vec::new();
        let mut unresolved = Vec::new();
        for mut child in std::mem::take(&mut inner.retained_children) {
            match child.retry() {
                Ok(()) => {}
                Err(_) => {
                    unresolved.push(child.resource.clone());
                    retained.push(child);
                }
            }
        }
        inner.retained_children = retained;
        unresolved
    }

    /// Retry owned workspace removal; returns still-unresolved paths.
    pub fn retry_pending_workspaces(&self) -> Vec<String> {
        let mut inner = self.lock();
        let mut retained = Vec::new();
        let mut unresolved = Vec::new();
        for mut pending in std::mem::take(&mut inner.pending_workspaces) {
            match pending.root.close() {
                Ok(()) => {}
                Err(_) => {
                    unresolved.push(pending.resource.clone());
                    retained.push(pending);
                }
            }
        }
        inner.pending_workspaces = retained;
        unresolved
    }
}

/// `close()`: stop admission, retry retained cleanup, retain failures.
impl SessionResource for ApktoolState {
    fn close(&self) -> Result<(), AnalysisError> {
        {
            let mut inner = self.lock();
            inner.closing = true;
        }
        let mut resources = self.retry_retained_children();
        resources.extend(self.retry_pending_workspaces());
        if resources.is_empty() {
            return Ok(());
        }
        let mut deduped: Vec<String> = Vec::new();
        for resource in resources {
            if !deduped.contains(&resource) {
                deduped.push(resource);
            }
        }
        let diagnostics = crate::common::errors::object(serde_json::json!({
            "reason": "Apktool cleanup remains incomplete",
        }));
        Err(provider_cleanup(
            APKTOOL_PROVIDER_ID,
            "close",
            deduped,
            diagnostics,
        ))
    }
}

/// Register the Apktool state as a shutdown resource once per session.
pub fn state(session: &Arc<Session>) -> Arc<ApktoolState> {
    let state = session.state::<ApktoolState>();
    session.own_once(Arc::clone(&state));
    state
}
