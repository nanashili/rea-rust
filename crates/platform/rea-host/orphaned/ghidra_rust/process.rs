//! Typed observation boundary for a Rust Ghidra worker process.
//!
//! This module owns the worker-facing lifecycle shape while delegating process
//! groups, pipes, and platform cleanup to [`process_launcher`].  It deliberately
//! reports captured bytes and exit facts without interpreting worker protocol
//! frames; protocol decoding belongs to the provider boundary.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::{
    process::launcher::{
        ChildCompletion, ChildExit, ChildLaunchSpec, ChildOutput, JobSettlement,
        OwnedChildProcess, ProcessLaunchError,
    },
    process::windows::job::WindowsJobLimits,
};

const DEFAULT_EXIT_CODE_ON_CANCEL: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerProcessConfig {
    pub executable: PathBuf,
    /// Exact worker argv entries after the program.
    pub arguments: Vec<OsString>,
    pub working_directory: Option<PathBuf>,
    pub protocol_stdin: bool,
    pub limits: WindowsJobLimits,
}

impl WorkerProcessConfig {
    pub fn validate(&self) -> Result<(), WorkerProcessError> {
        if !self.executable.is_absolute() {
            return Err(WorkerProcessError::configuration(
                "worker executable must be an absolute path",
            ));
        }

        self.limits
            .validate()
            .map_err(WorkerProcessError::configuration)
    }

    fn launch_spec(&self) -> ChildLaunchSpec {
        ChildLaunchSpec {
            executable: self.executable.clone(),
            arguments: self.arguments.clone(),
            working_directory: self.working_directory.clone(),
            protocol_stdin: self.protocol_stdin,
            limits: self.limits,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerExit {
    pub code: u32,
}

impl From<ChildExit> for WorkerExit {
    fn from(exit: ChildExit) -> Self {
        Self { code: exit.code }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkerProcessObservation {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_closed: bool,
    pub stderr_closed: bool,
    pub output_incomplete: bool,
    pub cancellation_observed: bool,
    pub exit: Option<WorkerExit>,
    pub settlement: Option<JobSettlement>,
}

impl WorkerProcessObservation {
    fn update_output(&mut self, output: ChildOutput) {
        self.stdout = output.stdout;
        self.stderr = output.stderr;
        self.stdout_closed = output.stdout_closed;
        self.stderr_closed = output.stderr_closed;
        self.output_incomplete = output.output_incomplete;
        self.cancellation_observed = output.cancellation_observed;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerProcessState {
    Running,
    Exited,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerProcessError {
    Configuration(String),
    Launch(ProcessLaunchError),
    InvalidState { operation: &'static str, state: WorkerProcessState },
}

impl WorkerProcessError {
    fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration(message.into())
    }

    fn invalid_state(operation: &'static str, state: WorkerProcessState) -> Self {
        Self::InvalidState { operation, state }
    }
}

impl std::fmt::Display for WorkerProcessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(message) => formatter.write_str(message),
            Self::Launch(error) => write!(formatter, "{}: {}", error.operation, error.message),
            Self::InvalidState { operation, state } => {
                write!(formatter, "cannot {operation} while worker is {state:?}")
            }
        }
    }
}

impl std::error::Error for WorkerProcessError {}

impl From<ProcessLaunchError> for WorkerProcessError {
    fn from(error: ProcessLaunchError) -> Self {
        Self::Launch(error)
    }
}

pub struct GhidraRustWorkerProcess {
    executable: PathBuf,
    child: OwnedChildProcess,
    state: WorkerProcessState,
    observation: WorkerProcessObservation,
}

impl GhidraRustWorkerProcess {
    pub fn start(config: WorkerProcessConfig) -> Result<Self, WorkerProcessError> {
        config.validate()?;

        let child = OwnedChildProcess::launch(config.launch_spec())?;
        Ok(Self {
            executable: config.executable,
            child,
            state: WorkerProcessState::Running,
            observation: WorkerProcessObservation::default(),
        })
    }

    pub fn state(&self) -> WorkerProcessState {
        self.state
    }

    pub fn observation(&self) -> &WorkerProcessObservation {
        &self.observation
    }

    pub fn write_stdin(&self, bytes: &[u8]) -> Result<usize, WorkerProcessError> {
        self.require_running("write worker stdin")?;
        Ok(self.child.write_input(bytes)?)
    }

    pub fn close_stdin(&mut self) -> Result<(), WorkerProcessError> {
        self.require_running("close worker stdin")?;
        self.child.close_input();
        Ok(())
    }

    pub fn observe(&mut self) -> Result<&WorkerProcessObservation, WorkerProcessError> {
        self.refresh_output()?;

        if self.state == WorkerProcessState::Running {
            if let Some(exit) = self.child.try_wait()? {
                self.record_exit(exit, None);
            }
        }

        Ok(&self.observation)
    }

    /// Observe output while allowing the caller to stop a bounded drain.
    ///
    /// The worker protocol can leave stdout or stderr open after the process
    /// has produced its final frame.  The TypeScript owner keeps cancellation
    /// active while it drains those streams, so this variant preserves the
    /// same ownership boundary without making the process object know about a
    /// particular cancellation primitive.
    pub fn observe_with_cancel<F>(
        &mut self,
        cancelled: F,
    ) -> Result<&WorkerProcessObservation, WorkerProcessError>
    where
        F: Fn() -> bool,
    {
        self.refresh_output_with_cancel(cancelled)?;

        if self.state == WorkerProcessState::Running {
            if let Some(exit) = self.child.try_wait()? {
                self.record_exit(exit, None);
            }
        }

        Ok(&self.observation)
    }

    pub fn wait(&mut self) -> Result<&WorkerProcessObservation, WorkerProcessError> {
        self.require_running("wait for worker exit")?;

        let completion = self.child.wait_with_settlement()?;
        self.record_completion(completion);
        self.refresh_output()?;
        Ok(&self.observation)
    }

    pub fn drain_output(&mut self) -> Result<&WorkerProcessObservation, WorkerProcessError> {
        let output = self.child.drain_output()?;
        self.observation.update_output(output);
        Ok(&self.observation)
    }

    /// Drain captured worker output with a caller-owned cancellation check.
    ///
    /// The launcher retains the child and its streams when cancellation cuts
    /// the drain short.  Keeping that behavior here lets callers preserve
    /// incomplete output and retry cleanup instead of dropping recovery data.
    pub fn drain_output_with_cancel<F>(
        &mut self,
        cancelled: F,
    ) -> Result<&WorkerProcessObservation, WorkerProcessError>
    where
        F: Fn() -> bool,
    {
        let output = self.child.drain_output_with(cancelled)?;
        self.observation.update_output(output);
        Ok(&self.observation)
    }

    pub fn cancel(&mut self) -> Result<&WorkerProcessObservation, WorkerProcessError> {
        if self.state != WorkerProcessState::Running {
            return Err(WorkerProcessError::invalid_state("cancel worker", self.state));
        }

        self.child.cancel(DEFAULT_EXIT_CODE_ON_CANCEL)?;
        self.state = WorkerProcessState::Cancelled;
        self.refresh_output()?;
        self.observation.settlement = Some(self.child.settlement()?);
        Ok(&self.observation)
    }

    pub fn retry_cleanup(&mut self) -> Result<(), WorkerProcessError> {
        self.child.retry_cleanup(DEFAULT_EXIT_CODE_ON_CANCEL)?;
        Ok(())
    }

    pub fn executable(&self) -> &Path {
        self.executable.as_path()
    }

    fn require_running(&self, operation: &'static str) -> Result<(), WorkerProcessError> {
        if self.state == WorkerProcessState::Running {
            Ok(())
        } else {
            Err(WorkerProcessError::invalid_state(operation, self.state))
        }
    }

    fn refresh_output(&mut self) -> Result<(), WorkerProcessError> {
        let output = self.child.read_output()?;
        self.observation.update_output(output);
        Ok(())
    }

    fn refresh_output_with_cancel<F>(&mut self, cancelled: F) -> Result<(), WorkerProcessError>
    where
        F: Fn() -> bool,
    {
        let output = self.child.drain_output_with(cancelled)?;
        self.observation.update_output(output);
        Ok(())
    }

    fn record_exit(&mut self, exit: ChildExit, settlement: Option<JobSettlement>) {
        self.state = WorkerProcessState::Exited;
        self.observation.exit = Some(exit.into());
        self.observation.settlement = settlement;
    }

    fn record_completion(&mut self, completion: ChildCompletion) {
        self.record_exit(completion.exit, Some(completion.settlement));
    }
}
