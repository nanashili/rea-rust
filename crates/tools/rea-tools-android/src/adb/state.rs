//! Per-session ADB provider state and its shutdown resource.
//!
//! Compatibility owner: the owned-resource and `close()` lifecycle of
//! `AdbProvider` in `src/adb/AdbProvider.ts`. One session owns one provider.
//! Operations run concurrently, as the original provider admits them; each
//! one is tracked as active so `close()` stops admission, joins every active
//! operation, then retries retained process cleanup and owned output-directory
//! removal. A failed retry keeps ownership for a later retry.
use crate::common::errors::provider_cleanup;
use crate::common::process::RetainedChild;
use rea_core::analysis_error::AnalysisError;
use rea_mcp::{Session, SessionResource};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use super::provider::ADB_PROVIDER_ID;

/// One owned output directory whose removal failed and must be retried.
pub struct PendingOutputDirectory {
    pub path: String,
    /// Identity captured when the directory was created (dev, ino, mode).
    pub identity: Option<super::files::OutputDirectoryIdentity>,
    pub primary: AnalysisError,
}

/// Session-scoped ADB state.
#[derive(Default)]
pub struct AdbState {
    inner: Mutex<AdbStateInner>,
    /// Active operation count, joined by `close()`.
    active: Mutex<usize>,
    settled: Condvar,
}

#[derive(Default)]
struct AdbStateInner {
    retained_children: Vec<RetainedChild>,
    pending_directories: Vec<PendingOutputDirectory>,
    closing: bool,
}

/// Marks one admitted operation active until dropped.
pub struct ActiveOperation<'a> {
    state: &'a AdbState,
}

impl Drop for ActiveOperation<'_> {
    fn drop(&mut self) {
        let mut active = self
            .state
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *active = active.saturating_sub(1);
        drop(active);
        self.state.settled.notify_all();
    }
}

/// Unresolved cleanup after a retry: resource labels and failure reasons.
#[derive(Default)]
pub struct Unresolved {
    pub resources: Vec<String>,
    pub reasons: Vec<String>,
}

impl Unresolved {
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    fn extend(&mut self, other: Unresolved) {
        for resource in other.resources {
            if !self.resources.contains(&resource) {
                self.resources.push(resource);
            }
        }
        self.reasons.extend(other.reasons);
    }

    /// `causes.map(message).join("; ")`.
    pub fn reason(&self) -> String {
        self.reasons.join("; ")
    }
}

impl AdbState {
    fn lock(&self) -> MutexGuard<'_, AdbStateInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Admit one operation unless the provider is closing.
    pub fn enter(&self) -> Option<ActiveOperation<'_>> {
        let inner = self.lock();
        if inner.closing {
            return None;
        }
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *active += 1;
        drop(active);
        drop(inner);
        Some(ActiveOperation { state: self })
    }

    /// Retain a child whose owned cleanup could not be confirmed.
    pub fn retain_child(&self, child: RetainedChild) {
        self.lock().retained_children.push(child);
    }

    /// Retain an owned output directory for cleanup retry.
    pub fn retain_directory(&self, directory: PendingOutputDirectory) {
        self.lock().pending_directories.push(directory);
    }

    /// Retry retained process cleanup, as `ArtifactResourceScope.retryCleanup`
    /// runs before each operation.
    pub fn retry_retained_children(&self) -> Unresolved {
        let mut inner = self.lock();
        let mut retained = Vec::new();
        let mut unresolved = Unresolved::default();
        for mut child in std::mem::take(&mut inner.retained_children) {
            if let Err(reason) = child.retry() {
                unresolved.resources.push(child.resource.clone());
                unresolved.reasons.push(reason);
                retained.push(child);
            }
        }
        inner.retained_children = retained;
        unresolved
    }

    /// Retry owned output-directory cleanup (`#retryOutputDirectoryCleanup`).
    pub fn retry_pending_directories(&self) -> Unresolved {
        let mut inner = self.lock();
        let mut retained = Vec::new();
        let mut unresolved = Unresolved::default();
        for pending in std::mem::take(&mut inner.pending_directories) {
            match super::files::remove_owned_output_directory(&pending.path, pending.identity) {
                // Removal resolves the retained owner. The primary's own process
                // cleanup is tracked separately by the retained children.
                Ok(()) => {}
                Err(error) => {
                    unresolved.resources.push(pending.path.clone());
                    unresolved.reasons.push(error.to_string());
                    retained.push(pending);
                }
            }
        }
        inner.pending_directories = retained;
        unresolved
    }

    /// Whether output-directory cleanup is pending.
    pub fn has_pending_directories(&self) -> bool {
        !self.lock().pending_directories.is_empty()
    }
}

/// `close()`: stop admission, join active work, retry retained cleanup.
impl SessionResource for AdbState {
    fn close(&self) -> Result<(), AnalysisError> {
        self.lock().closing = true;
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        while *active > 0 {
            active = self
                .settled
                .wait(active)
                .unwrap_or_else(|poison| poison.into_inner());
        }
        drop(active);
        let mut unresolved = self.retry_retained_children();
        unresolved.extend(self.retry_pending_directories());
        if unresolved.is_empty() {
            return Ok(());
        }
        let diagnostics = crate::common::errors::object(serde_json::json!({
            "reason": unresolved.reason(),
        }));
        Err(provider_cleanup(
            ADB_PROVIDER_ID,
            "close_binary",
            unresolved.resources,
            diagnostics,
        ))
    }
}

/// Register the ADB state as a shutdown resource once per session and return it.
pub fn state(session: &Arc<Session>) -> Arc<AdbState> {
    let state = session.state::<AdbState>();
    session.own_once(Arc::clone(&state));
    state
}
