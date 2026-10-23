//! Ownership boundary for one Rust Ghidra worker.
//!
//! The process launcher owns the authority to stop a worker and verifies its
//! process identity before doing so.  This type owns the surrounding worker
//! lifecycle: process-family observations, bounded diagnostics, and retryable
//! release of the process and its dependent resources.

use std::{
    thread,
    time::{Duration, Instant},
};

use crate::{
    ghidra_rust::process_cleanup::{GhidraRustCleanupFailure, GhidraRustProcessCleanup},
    process::launcher::{ChildOutput, OwnedChildProcess, ProcessLaunchError},
    process::observation::{self as process_observation, LineageObservation, ProcessIdentitySource},
};

const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Identity facts captured for the worker before family observations begin.
///
/// Optional relation fields intentionally remain optional.  A missing native
/// relation is unknown and must not be treated as proof that the worker has no
/// process family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhidraRustWorkerIdentity {
    pub pid: u64,
    pub identity: String,
    pub process_group_id: Option<u64>,
}

/// A verified process family, or an explicit inability to verify it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GhidraRustProcessFamily {
    Verified {
        root: process_observation::LineageNode,
        descendants: Vec<process_observation::LineageNode>,
    },
    Unavailable { reason: String },
}

impl From<LineageObservation> for GhidraRustProcessFamily {
    fn from(observation: LineageObservation) -> Self {
        match observation {
            LineageObservation::Verified { root, descendants } => Self::Verified {
                root,
                descendants,
            },
            LineageObservation::Unavailable { reason } => Self::Unavailable { reason },
        }
    }
}

/// Facts retained after the worker has exited or while cleanup is pending.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GhidraRustWorkerDiagnostics {
    pub exit_code: Option<u32>,
    pub stderr: String,
    pub stderr_truncated: bool,
    pub output_incomplete: bool,
    pub active_processes: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhidraRustCleanupError {
    pub failures: Vec<GhidraRustCleanupFailure>,
}

impl std::fmt::Display for GhidraRustCleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} Ghidra Rust worker cleanup phase(s) failed", self.failures.len())
    }
}

impl std::error::Error for GhidraRustCleanupError {}

/// Owns a worker until process, lineage, and stream cleanup have all settled.
pub struct GhidraRustProcessOwner {
    identity: GhidraRustWorkerIdentity,
    child: Option<OwnedChildProcess>,
    cleanup: GhidraRustProcessCleanup,
    diagnostics: GhidraRustWorkerDiagnostics,
    family: Option<GhidraRustProcessFamily>,
}

impl GhidraRustProcessOwner {
    /// Adopt a process only after the launcher has established its ownership.
    pub fn adopt(identity: GhidraRustWorkerIdentity, child: OwnedChildProcess) -> Self {
        Self {
            identity,
            child: Some(child),
            cleanup: GhidraRustProcessCleanup::owned(),
            diagnostics: GhidraRustWorkerDiagnostics::default(),
            family: None,
        }
    }

    pub fn identity(&self) -> &GhidraRustWorkerIdentity {
        &self.identity
    }

    pub fn child(&self) -> Option<&OwnedChildProcess> {
        self.child.as_ref()
    }

    pub fn child_mut(&mut self) -> Option<&mut OwnedChildProcess> {
        self.child.as_mut()
    }

    pub fn family(&self) -> Option<&GhidraRustProcessFamily> {
        self.family.as_ref()
    }

    pub fn diagnostics(&self) -> &GhidraRustWorkerDiagnostics {
        &self.diagnostics
    }

    pub fn cleanup(&self) -> &GhidraRustProcessCleanup {
        &self.cleanup
    }

    /// Observe the worker and its caller-selected descendants twice.
    ///
    /// The shared observer preserves generation changes and unreadable native
    /// facts as `Unavailable`; this owner only adds the worker's captured
    /// identity and process-group constraints.
    pub fn observe_process_family<S, C>(
        &mut self,
        source: &S,
        candidates: C,
        max_nodes: usize,
    ) -> &GhidraRustProcessFamily
    where
        S: ProcessIdentitySource,
        C: IntoIterator<Item = u64>,
    {
        let mut observation = process_observation::observe_process_lineages(
            source,
            [self.identity.pid],
            candidates,
            false,
            max_nodes,
        )
        .remove(&self.identity.pid)
        .unwrap_or_else(|| LineageObservation::Unavailable {
            reason: "worker lineage observation did not return its root".into(),
        });

        if let LineageObservation::Verified { root, descendants } = &observation {
            if root.identity != self.identity.identity
                || self.identity.process_group_id.is_some_and(|expected| {
                    root.process_group_id != Some(expected)
                        || descendants
                            .iter()
                            .any(|node| node.process_group_id != Some(expected))
                })
            {
                observation = LineageObservation::Unavailable {
                    reason: "worker process-family identity could not be revalidated".into(),
                };
            }
        }

        self.family = Some(observation.into());
        self.family.as_ref().expect("family was just stored")
    }

    /// Wait for the child, retain its final diagnostics, and settle its family.
    pub fn wait_for_exit(&mut self, timeout: Duration) -> Result<(), ProcessLaunchError> {
        let deadline = Instant::now() + timeout;
        loop {
            let Some(child) = self.child.as_ref() else {
                return Ok(());
            };
            if child.try_wait()?.is_some() {
                let child = self
                    .child
                    .as_mut()
                    .expect("child remains owned after try_wait");
                let exit = child.wait()?;
                let output = child.drain_output()?;
                let active_processes = child.active_processes()?;
                self.record_exit(exit.code, output, active_processes);
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ProcessLaunchError {
                    operation: "wait_for_exit",
                    message: "worker did not exit before the deadline".into(),
                    cleanup: None,
                });
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    /// Release all independent resources and retain ownership on any failure.
    pub fn release(&mut self) -> Result<(), GhidraRustCleanupError> {
        self.release_with(|| Ok(()), || Ok(()), || Ok(()))
    }

    /// Release process, lineage, protocol, and listener resources.
    ///
    /// Every phase is attempted on every call. The `OwnedChildProcess` remains
    /// in this owner until every phase succeeds so a later call can retry any
    /// failed cleanup while retaining the original launch authority.
    pub fn release_with<Lineage, Protocol, Listeners>(
        &mut self,
        mut settle_lineage: Lineage,
        release_protocol: Protocol,
        release_listeners: Listeners,
    ) -> Result<(), GhidraRustCleanupError>
    where
        Lineage: FnMut() -> Result<(), String>,
        Protocol: FnOnce() -> Result<(), String>,
        Listeners: FnOnce() -> Result<(), String>,
    {
        let mut child = self.child.take();
        let mut release_diagnostics = None;
        self.cleanup.attempt(
            || {
                let Some(process) = child.as_mut() else {
                    return Ok(());
                };

                match Self::stop_and_collect_diagnostics(process) {
                    Ok(diagnostics) => {
                        release_diagnostics = Some(diagnostics);
                        Ok(())
                    }
                    Err((diagnostics, failure)) => {
                        release_diagnostics = Some(diagnostics);
                        Err(failure)
                    }
                }
            },
            || Self::settle_lineage_observations(&mut settle_lineage),
            release_protocol,
            release_listeners,
        );

        if let Some(diagnostics) = release_diagnostics {
            self.diagnostics = diagnostics;
        }

        if self.cleanup.is_complete() {
            child = None;
        }

        self.child = child;

        if self.cleanup.is_complete() {
            Ok(())
        } else {
            Err(GhidraRustCleanupError {
                failures: self.cleanup.failures().to_vec(),
            })
        }
    }

    fn record_exit(&mut self, exit_code: u32, output: ChildOutput, active_processes: u32) {
        self.diagnostics.exit_code = Some(exit_code);
        let retained = output.stderr.len().min(MAX_DIAGNOSTIC_BYTES);
        self.diagnostics.stderr = String::from_utf8_lossy(&output.stderr[..retained]).into_owned();
        self.diagnostics.stderr_truncated = output.stderr.len() > retained;
        self.diagnostics.output_incomplete = output.output_incomplete;
        self.diagnostics.active_processes = Some(active_processes);
    }

    /// Stop the owned process and retain the same final diagnostics that are
    /// available when the worker exits through the normal wait path.
    ///
    /// Cleanup and output capture are independent observations.  We attempt
    /// both even when stopping the process fails so a later retry retains the
    /// most useful evidence while ownership remains with this owner.
    fn stop_and_collect_diagnostics(
        process: &mut OwnedChildProcess,
    ) -> Result<GhidraRustWorkerDiagnostics, (GhidraRustWorkerDiagnostics, String)> {
        let mut failures = Vec::new();
        let exit_before_stop = match process.try_wait() {
            Ok(exit) => exit,
            Err(error) => {
                failures.push(error.to_string());
                None
            }
        };

        if let Err(error) = process.cancel(1) {
            failures.push(error.to_string());
        }

        let exit = exit_before_stop.or_else(|| match process.try_wait() {
            Ok(exit) => exit,
            Err(error) => {
                failures.push(error.to_string());
                None
            }
        });

        let output = match process.drain_output() {
            Ok(output) => Some(output),
            Err(error) => {
                failures.push(error.to_string());
                None
            }
        };
        let active_processes = match process.active_processes() {
            Ok(active_processes) => Some(active_processes),
            Err(error) => {
                failures.push(error.to_string());
                None
            }
        };

        let mut diagnostics = GhidraRustWorkerDiagnostics {
            exit_code: exit.map(|value| value.code),
            active_processes,
            ..GhidraRustWorkerDiagnostics::default()
        };

        if let Some(output) = output {
            diagnostics.stderr = String::from_utf8_lossy(
                &output.stderr[..output.stderr.len().min(MAX_DIAGNOSTIC_BYTES)],
            )
            .into_owned();
            diagnostics.stderr_truncated = output.stderr.len() > MAX_DIAGNOSTIC_BYTES;
            diagnostics.output_incomplete = output.output_incomplete;
        }

        if failures.is_empty() {
            Ok(diagnostics)
        } else {
            Err((diagnostics, failures.join("; ")))
        }
    }

    /// Settle both the observation that was active before cleanup and a fresh
    /// observation after the process stop. The second observation closes the
    /// race where descendants appear or disappear while the worker exits.
    fn settle_lineage_observations<Lineage>(
        settle_lineage: &mut Lineage,
    ) -> Result<(), String>
    where
        Lineage: FnMut() -> Result<(), String>,
    {
        let first = settle_lineage();
        let second = settle_lineage();

        match (first, second) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(first), Ok(())) => Err(format!(
                "initial lineage settlement failed: {first}"
            )),
            (Ok(()), Err(second)) => Err(format!(
                "final lineage settlement failed: {second}"
            )),
            (Err(first), Err(second)) => Err(format!(
                "initial lineage settlement failed: {first}; final lineage settlement failed: {second}"
            )),
        }
    }
}

