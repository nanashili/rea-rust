//! Bounded worker-output draining after an unexpected process exit.
//!
//! Protocol bytes and diagnostics have different owners.  Standard output is
//! decoded as JSONL frames, while standard error is retained only as bounded
//! diagnostic text.  The drain remains pending briefly so bytes already in the
//! inherited pipes can be observed without waiting indefinitely.

use std::time::{Duration, Instant};

use crate::{
    ghidra_rust::protocol::{LineDecoder, WorkerFrame},
    process::launcher::ChildOutput,
};

pub const EXIT_DRAIN_TIMEOUT: Duration = Duration::from_millis(1_000);
pub const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerExit {
    pub code: Option<i32>,
    pub signal: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExitDrainFailure {
    ProcessExited { exit: WorkerExit, diagnostics: String },
    IncompleteOutput {
        stdout_closed: bool,
        stderr_closed: bool,
        output_incomplete: bool,
    },
    Protocol(String),
    DiagnosticsLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainedOutput {
    pub frames: Vec<WorkerFrame>,
    pub diagnostics: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainState {
    Waiting,
    Complete,
    Failed,
}

/// Tracks one exit drain.  `ChildOutput` is a cumulative snapshot, so this
/// type retains offsets and admits only newly observed bytes.
pub struct ExitDrain {
    decoder: LineDecoder,
    frames: Vec<WorkerFrame>,
    diagnostics: Vec<u8>,
    stdout_read: usize,
    stderr_read: usize,
    deadline: Option<Instant>,
    exit: Option<WorkerExit>,
    failure: Option<ExitDrainFailure>,
}

impl Default for ExitDrain {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitDrain {
    pub fn new() -> Self {
        Self {
            decoder: LineDecoder::new(),
            frames: Vec::new(),
            diagnostics: Vec::new(),
            stdout_read: 0,
            stderr_read: 0,
            deadline: None,
            exit: None,
            failure: None,
        }
    }

    /// Records the process exit and starts the bounded inherited-pipe drain.
    pub fn observe_exit(&mut self, code: Option<i32>, signal: Option<String>, now: Instant) {
        if self.exit.is_some() || self.failure.is_some() {
            return;
        }

        let exit = WorkerExit { code, signal };
        self.exit = Some(exit.clone());
        self.failure = Some(ExitDrainFailure::ProcessExited {
            exit,
            diagnostics: String::new(),
        });
        self.deadline = Some(now + EXIT_DRAIN_TIMEOUT);
    }

    /// Admits the latest cumulative output snapshot and returns its state.
    pub fn poll(&mut self, output: &ChildOutput, now: Instant) -> DrainState {
        if self.is_terminal_failure() {
            return DrainState::Failed;
        }

        if let Err(failure) = self.admit_output(output) {
            self.failure = Some(failure);
            return DrainState::Failed;
        }

        if output.output_incomplete || !output.stdout_closed || !output.stderr_closed {
            if self.deadline.is_some_and(|deadline| now >= deadline) {
                self.failure = Some(ExitDrainFailure::IncompleteOutput {
                    stdout_closed: output.stdout_closed,
                    stderr_closed: output.stderr_closed,
                    output_incomplete: output.output_incomplete,
                });
                return DrainState::Failed;
            }
            return DrainState::Waiting;
        }

        if let Err(message) = std::mem::take(&mut self.decoder).finish() {
            self.failure = Some(ExitDrainFailure::Protocol(message));
            return DrainState::Failed;
        }

        if let Some(exit) = self.exit.clone() {
            self.failure = Some(ExitDrainFailure::ProcessExited {
                exit,
                diagnostics: String::from_utf8_lossy(&self.diagnostics).into_owned(),
            });
            return DrainState::Failed;
        }

        DrainState::Complete
    }

    pub fn output(&self) -> DrainedOutput {
        DrainedOutput {
            frames: self.frames.clone(),
            diagnostics: String::from_utf8_lossy(&self.diagnostics).into_owned(),
        }
    }

    pub fn failure(&self) -> Option<&ExitDrainFailure> {
        self.failure.as_ref()
    }

    pub fn exit(&self) -> Option<&WorkerExit> {
        self.exit.as_ref()
    }

    /// Stops the timer while preserving already captured output.
    pub fn dispose(&mut self) {
        self.deadline = None;
    }

    fn admit_output(&mut self, output: &ChildOutput) -> Result<(), ExitDrainFailure> {
        if output.stdout.len() < self.stdout_read || output.stderr.len() < self.stderr_read {
            return Err(ExitDrainFailure::Protocol(
                "worker output regressed during exit drain".into(),
            ));
        }

        let stdout = &output.stdout[self.stdout_read..];
        let stderr = &output.stderr[self.stderr_read..];
        self.stdout_read = output.stdout.len();
        self.stderr_read = output.stderr.len();

        if self.diagnostics.len().saturating_add(stderr.len()) > MAX_DIAGNOSTIC_BYTES {
            return Err(ExitDrainFailure::DiagnosticsLimit);
        }
        self.diagnostics.extend_from_slice(stderr);
        let frames = self
            .decoder
            .push(stdout)
            .map_err(ExitDrainFailure::Protocol)?;
        self.frames.extend(frames);

        Ok(())
    }

    fn is_terminal_failure(&self) -> bool {
        matches!(
            self.failure.as_ref(),
            Some(
                ExitDrainFailure::IncompleteOutput { .. }
                    | ExitDrainFailure::Protocol(_)
                    | ExitDrainFailure::DiagnosticsLimit
            )
        )
    }
}

