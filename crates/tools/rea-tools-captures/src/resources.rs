//! Admission, producer cleanup and private workspaces owned together.
//!
//! Compatibility owner: `src/process/ArtifactAnalysisResources.ts`. One
//! provider instance admits one request at a time, retains every private
//! runtime root (and any producer whose cleanup failed) until cleanup is
//! confirmed, and composes late cleanup failures with the primary outcome.
use crate::artifact::{ReadError, ReaderReason};
use crate::errors::{self, map};
use crate::limits::LinuxLimits;
use crate::process::{CommandFailure, FailureReason, OwnedProcess, StopResult};
use crate::runtime::RuntimeRoot;
use rea_core::analysis_error::{AnalysisError, CapturedOutput};
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use std::sync::{Mutex, MutexGuard};

/// One retained private root and the producer that may still use it.
struct Pending {
    id: u64,
    root: RuntimeRoot,
    owner: Option<OwnedProcess>,
    operation: String,
}

#[derive(Default)]
struct State {
    busy: bool,
    closed: bool,
    pending: Vec<Pending>,
    next_id: u64,
    operation: String,
}

/// Handle to one retained root inside the resources owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootId(u64);

/// Admission and cleanup owner for one provider instance.
pub struct AnalysisResources {
    provider_id: &'static str,
    operation: &'static str,
    capacity_message: &'static str,
    capacity_details: fn() -> Value,
    state: Mutex<State>,
}

impl AnalysisResources {
    pub const fn new(
        provider_id: &'static str,
        operation: &'static str,
        capacity_message: &'static str,
        capacity_details: fn() -> Value,
    ) -> Self {
        Self {
            provider_id,
            operation,
            capacity_message,
            capacity_details,
            state: Mutex::new(State {
                busy: false,
                closed: false,
                pending: Vec::new(),
                next_id: 0,
                operation: String::new(),
            }),
        }
    }

    pub fn provider_id(&self) -> &'static str {
        self.provider_id
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Admit one request at a time (`run`).
    pub fn run<T>(
        &self,
        operation: &str,
        cancellation: &Cancellation,
        work: impl FnOnce() -> Result<T, AnalysisError>,
    ) -> Result<T, AnalysisError> {
        {
            let mut state = self.lock();
            if state.closed || cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled(operation));
            }
            if state.busy {
                return Err(AnalysisError::resource_constraint(
                    operation,
                    "capacity",
                    self.capacity_message,
                    Some((self.capacity_details)()),
                ));
            }
            state.busy = true;
            state.operation = operation.to_owned();
        }
        struct Release<'a>(&'a AnalysisResources);
        impl Drop for Release<'_> {
            fn drop(&mut self) {
                self.0.lock().busy = false;
            }
        }
        let _release = Release(self);
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        work()
    }

    /// Retain a private root until its cleanup succeeds.
    pub fn retain_root(&self, root: RuntimeRoot) -> RootId {
        let mut state = self.lock();
        let id = state.next_id;
        state.next_id += 1;
        let operation = state.operation.clone();
        state.pending.push(Pending {
            id,
            root,
            owner: None,
            operation,
        });
        RootId(id)
    }

    /// Attach a producer whose cleanup failed to its retained root.
    pub fn retain_owner(&self, root: RootId, owner: OwnedProcess) {
        let mut state = self.lock();
        if let Some(pending) = state
            .pending
            .iter_mut()
            .find(|pending| pending.id == root.0)
        {
            pending.owner = Some(owner);
        }
    }

    /// Path of a retained root.
    pub fn root_path(&self, root: RootId) -> Option<String> {
        self.lock()
            .pending
            .iter()
            .find(|pending| pending.id == root.0)
            .map(|pending| pending.root.path().to_owned())
    }

    fn resources_for(pending: &Pending) -> Vec<String> {
        match &pending.owner {
            None => vec![pending.root.path().to_owned()],
            Some(owner) => owner.resources(Some(pending.root.path())),
        }
    }

    fn pending_resources(state: &State) -> Vec<String> {
        state.pending.iter().flat_map(Self::resources_for).collect()
    }

    /// Release every retained root, keeping failed owners (`release`).
    pub fn release(&self) -> Result<(), AnalysisError> {
        let mut state = self.lock();
        let mut failures = Vec::new();
        let mut index = 0;
        while index < state.pending.len() {
            let provider_id = self.provider_id;
            let pending = &mut state.pending[index];
            let outcome = Self::release_root(provider_id, pending);
            match outcome {
                Ok(()) => {
                    state.pending.remove(index);
                }
                Err(failure) => {
                    failures.push(failure);
                    index += 1;
                }
            }
        }
        match failures.len() {
            0 => Ok(()),
            1 => Err(failures.remove(0)),
            _ => {
                let resources = failures
                    .iter()
                    .flat_map(AnalysisError::unresolved_resources)
                    .collect::<Vec<_>>();
                let operation = failures
                    .first()
                    .and_then(|failure| match &failure.kind {
                        rea_core::analysis_error::ErrorKind::ProviderAdapter {
                            operation, ..
                        } => Some(operation.clone()),
                        _ => None,
                    })
                    .unwrap_or_else(|| state.operation.clone());
                Err(errors::provider_cleanup(
                    self.provider_id,
                    resources,
                    map([
                        (
                            "reason",
                            json!("One or more analysis runtime resources remain owned."),
                        ),
                        (
                            "failures",
                            Value::Array(failures.iter().map(AnalysisError::project).collect()),
                        ),
                    ]),
                    &operation,
                ))
            }
        }
    }

    fn release_root(provider_id: &str, pending: &mut Pending) -> Result<(), AnalysisError> {
        if let Some(owner) = pending.owner.as_mut() {
            if let StopResult::Incomplete { reason } = owner.stop() {
                return Err(errors::provider_cleanup(
                    provider_id,
                    Self::resources_for(pending),
                    map([("reason", json!(reason))]),
                    &pending.operation,
                ));
            }
            pending.owner = None;
        }
        if let Err(error) = pending.root.close() {
            return Err(errors::provider_cleanup(
                provider_id,
                Self::resources_for(pending),
                map([("reason", json!(format!("Error: {}", error.message)))]),
                &pending.operation,
            ));
        }
        Ok(())
    }

    /// Release, then compose cleanup with the primary outcome (`finish`).
    pub fn finish<T>(
        &self,
        result: Result<T, AnalysisError>,
        observation: impl Fn(&T) -> Option<Value>,
        operation: &str,
        cancellation: &Cancellation,
    ) -> Result<T, AnalysisError> {
        match self.release() {
            Ok(()) => match result {
                Ok(value) if cancellation.reason().is_some() => {
                    let mut error = AnalysisError::cancelled(operation);
                    if let Some(partial) = observation(&value) {
                        error = error.retain_partial_observation(partial);
                    }
                    Err(error)
                }
                other => other,
            },
            Err(cleanup) => {
                let (partial, primary) = match &result {
                    Ok(value) => {
                        let partial = observation(value);
                        let primary = cancellation.reason().is_some().then(|| {
                            let error = AnalysisError::cancelled(operation);
                            match &partial {
                                Some(partial) => error.retain_partial_observation(partial.clone()),
                                None => error,
                            }
                        });
                        (partial, primary)
                    }
                    Err(error) => (error.partial_observation.clone(), Some(error.clone())),
                };
                let mut failure = match primary {
                    Some(primary) => errors::with_cleanup_failure(primary, cleanup, operation),
                    None => cleanup,
                };
                if let Some(partial) = partial {
                    failure = failure.retain_partial_observation(partial);
                }
                Err(failure)
            }
        }
    }

    /// Classify an owned-command failure (`commandFailure`).
    pub fn command_failure(
        failure: &CommandFailure,
        command_timeout_ms: u64,
        output_bytes: u64,
        effective: Option<LinuxLimits>,
        operation: &str,
    ) -> AnalysisError {
        let captured = failure.snapshot.as_ref().map(errors::captured_from);
        let with = |error: AnalysisError| errors::with_output(error, captured.as_ref());
        match failure.reason {
            FailureReason::Cancelled => with(AnalysisError::cancelled(operation)),
            FailureReason::Timeout => with(AnalysisError::timeout(operation, command_timeout_ms)),
            FailureReason::OutputLimit => with(AnalysisError::resource_constraint(
                operation,
                "memory",
                failure.message.clone(),
                Some(json!({ "output_bytes": output_bytes })),
            )),
            FailureReason::Process => {
                let signal = failure
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.signal.as_deref());
                if let Some(signal @ ("SIGXFSZ" | "SIGXCPU")) = signal {
                    return with(AnalysisError::resource_constraint(
                        operation,
                        if signal == "SIGXFSZ" {
                            "file-size"
                        } else {
                            "cpu"
                        },
                        format!(
                            "Producer terminated with {signal}; the signal's exact cause is not independently established."
                        ),
                        effective.map(|limits| Value::Object(limits.to_map())),
                    ));
                }
                with(AnalysisError::output(operation, failure.message.clone()))
            }
        }
    }

    /// Compose a descriptor-cleanup read failure with its primary (`cleanupFailure`).
    pub fn read_cleanup_failure(
        &self,
        error: &ReadError,
        classify: impl Fn(&ReadError) -> AnalysisError,
        captured: Option<&CapturedOutput>,
        operation: &str,
    ) -> AnalysisError {
        let ReadError::Cleanup {
            primary,
            reason,
            resources,
        } = error
        else {
            return classify(error);
        };
        let mut diagnostics = map([("reason", json!(reason))]);
        if let Some(captured) = captured {
            diagnostics.insert("captured_output".into(), captured_value(captured));
        }
        let cleanup =
            errors::provider_cleanup(self.provider_id, resources.clone(), diagnostics, operation);
        let primary = primary.as_deref().map(|primary| {
            if primary.reader_reason() == Some(ReaderReason::Cancelled) {
                errors::with_output(AnalysisError::cancelled(operation), captured)
            } else {
                classify(primary)
            }
        });
        match primary {
            Some(primary) => errors::with_cleanup_failure(primary, cleanup, operation),
            None => cleanup,
        }
    }

    /// Close every retained resource at session end.
    pub fn close(&self) -> Result<(), AnalysisError> {
        self.lock().closed = true;
        self.release()
    }

    /// Paths of roots still retained.
    pub fn pending_paths(&self) -> Vec<String> {
        self.lock()
            .pending
            .iter()
            .map(|pending| pending.root.path().to_owned())
            .collect()
    }

    /// Every resource still retained.
    pub fn pending_resource_labels(&self) -> Vec<String> {
        Self::pending_resources(&self.lock())
    }

    /// Default operation for this owner.
    pub fn operation(&self) -> &'static str {
        self.operation
    }
}

/// Captured output as the diagnostic object the original copied verbatim.
pub fn captured_value(captured: &CapturedOutput) -> Value {
    let mut object = Map::new();
    object.insert("stdout".into(), json!(captured.stdout));
    object.insert("stderr".into(), json!(captured.stderr));
    object.insert("truncated".into(), json!(captured.truncated));
    if let Some(code) = &captured.exit_code {
        object.insert("exit_code".into(), json!(code));
    }
    if let Some(signal) = &captured.signal {
        object.insert("signal".into(), json!(signal));
    }
    Value::Object(object)
}
