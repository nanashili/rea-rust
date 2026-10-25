//! Owned child-process lifecycle boundary.
//!
//! The Windows implementation mirrors the native launcher lifecycle: the Job
//! Object is configured before process creation, the child starts suspended,
//! membership is verified before resume, and the Job remains owned through
//! settlement and cancellation.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::process::windows::job::WindowsJobLimits;

/// One owned child launch.
///
/// `arguments` are the exact argv entries after the program; they are never
/// re-split. Windows derives its CreateProcess command line from the
/// executable and these arguments using the MSVCRT quoting rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildLaunchSpec {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub working_directory: Option<PathBuf>,
    pub protocol_stdin: bool,
    pub limits: WindowsJobLimits,
}

impl ChildLaunchSpec {
    /// Collect caller-selected arguments without interpreting their contents.
    pub fn arguments<I, S>(arguments: I) -> Vec<OsString>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        arguments.into_iter().map(Into::into).collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildExit {
    pub code: u32,
    /// Terminating signal on Unix when the child did not exit normally.
    pub signal: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildCompletion {
    pub exit: ChildExit,
    pub settlement: JobSettlement,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChildOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_closed: bool,
    pub stderr_closed: bool,
    pub output_incomplete: bool,
    pub cancellation_observed: bool,
}

impl ChildOutput {
    pub fn exceeds_limit(&self, limit: usize) -> bool {
        self.stdout.len().saturating_add(self.stderr.len()) > limit
    }

    pub fn exceeds_stream_limit(&self, stdout_limit: usize, stderr_limit: usize) -> bool {
        self.stdout.len() > stdout_limit || self.stderr.len() > stderr_limit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobSettlement {
    pub active_processes: u32,
    pub peak_memory_bytes: u64,
    pub memory_limit_reached: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessLaunchError {
    pub operation: &'static str,
    pub message: String,
    pub cleanup: Option<String>,
}

impl std::fmt::Display for ProcessLaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.operation, self.message)?;

        if let Some(cleanup) = &self.cleanup {
            write!(formatter, " (cleanup failed: {cleanup})")?;
        }

        Ok(())
    }
}

impl std::error::Error for ProcessLaunchError {}

impl ProcessLaunchError {
    fn operation(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
            cleanup: None,
        }
    }

    #[cfg(windows)]
    fn with_cleanup(mut self, cleanup: String) -> Self {
        match self.cleanup.as_mut() {
            Some(previous) => {
                previous.push_str("; ");
                previous.push_str(&cleanup);
            }
            None => self.cleanup = Some(cleanup),
        }
        self
    }
}

#[cfg(not(windows))]
pub(crate) mod unix {
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::{
        ChildCompletion, ChildExit, ChildLaunchSpec, ChildOutput, JobSettlement, ProcessLaunchError,
    };
    use crate::process::linux::identity::{Observation, ProcessIdentityObserver};
    use crate::process::ownership::group_has_live_members;

    const READ_CHUNK_SIZE: usize = 64 * 1024;
    const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
    const DRAIN_DEADLINE: Duration = Duration::from_millis(250);

    #[derive(Debug, Default)]
    struct CapturedStream {
        bytes: Vec<u8>,
        closed: bool,
        truncated: bool,
    }

    #[derive(Debug)]
    pub(super) struct UnixChildProcess {
        child: Mutex<Child>,
        stdin: Mutex<Option<ChildStdin>>,
        stdout: Arc<Mutex<CapturedStream>>,
        stderr: Arc<Mutex<CapturedStream>>,
        process_group_id: libc::pid_t,
        process_identity: String,
        child_exit: Option<ChildExit>,
        child_reaped: bool,
        settled: bool,
        cleanup_failure: Option<ProcessLaunchError>,
    }

    impl UnixChildProcess {
        pub(super) fn launch(spec: ChildLaunchSpec) -> Result<Self, ProcessLaunchError> {
            Self::launch_with(spec, None, false).map(|(child, _)| child)
        }
        pub(super) fn launch_with(
            spec: ChildLaunchSpec,
            environment: Option<&[(std::ffi::OsString, std::ffi::OsString)]>,
            stream_stdout: bool,
        ) -> Result<(Self, Option<std::process::ChildStdout>), ProcessLaunchError> {
            Self::launch_bounded(spec, environment, stream_stdout, MAX_CAPTURE_BYTES)
        }
        /// Deliver `signal` to the owned process group after re-verifying its
        /// identity. A group that already exited is not an error.
        pub(super) fn signal_group(&self, signal: i32) -> Result<(), ProcessLaunchError> {
            if self.settled || self.child_reaped {
                return Ok(());
            }
            if peek_child_exit(self.process_group_id)?.is_none() {
                verify_group_owner(self.process_group_id, &self.process_identity)?;
            }
            // SAFETY: ownership was re-verified above; a negative pid targets
            // that owned process group and does not dereference a Rust pointer.
            let result = unsafe { libc::kill(-self.process_group_id, signal) };
            if result == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            Err(ProcessLaunchError::operation(
                "signal_process_group",
                error.to_string(),
            ))
        }

        /// Launch with an optional complete environment and a per-stream
        /// capture bound. A streamed stdout is returned unread to the caller
        /// instead of being captured here.
        pub(super) fn launch_bounded(
            spec: ChildLaunchSpec,
            environment: Option<&[(std::ffi::OsString, std::ffi::OsString)]>,
            stream_stdout: bool,
            max_capture_bytes: usize,
        ) -> Result<(Self, Option<std::process::ChildStdout>), ProcessLaunchError> {
            let mut command = Command::new(&spec.executable);
            command.args(&spec.arguments);
            if let Some(environment) = environment {
                command.env_clear();
                command.envs(environment.iter().map(|(key, value)| (key, value)));
            }
            configure_owned_process_group(&mut command)?;
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            command.stdin(if spec.protocol_stdin {
                Stdio::piped()
            } else {
                Stdio::null()
            });

            if let Some(directory) = spec.working_directory {
                command.current_dir(directory);
            }

            let mut child = command.spawn().map_err(|error| {
                ProcessLaunchError::operation("create_process", error.to_string())
            })?;
            let stdout = child.stdout.take().ok_or_else(|| {
                ProcessLaunchError::operation("capture_stdout", "child stdout was not piped")
            })?;
            let stderr = child.stderr.take().ok_or_else(|| {
                ProcessLaunchError::operation("capture_stderr", "child stderr was not piped")
            })?;

            let stdout_state = Arc::new(Mutex::new(CapturedStream::default()));
            let stderr_state = Arc::new(Mutex::new(CapturedStream::default()));
            let streamed = if stream_stdout {
                // The caller owns stdout framing; the captured view stays empty.
                if let Ok(mut capture) = stdout_state.lock() {
                    capture.closed = true;
                }
                Some(stdout)
            } else {
                spawn_capture_thread(stdout, Arc::clone(&stdout_state), max_capture_bytes);
                None
            };
            spawn_capture_thread(stderr, Arc::clone(&stderr_state), max_capture_bytes);

            let process_group_id = child.id().try_into().map_err(|_| {
                ProcessLaunchError::operation("observe_process_group", "child PID is out of range")
            })?;
            let process_identity = verify_owned_process_group(process_group_id)?;

            Ok((
                Self {
                    child: Mutex::new(child),
                    stdin: Mutex::new(None),
                    stdout: stdout_state,
                    stderr: stderr_state,
                    process_group_id,
                    process_identity,
                    child_exit: None,
                    child_reaped: false,
                    settled: false,
                    cleanup_failure: None,
                },
                streamed,
            ))
        }

        /// The owned process-group leader (equal to the child PID).
        pub(super) fn id(&self) -> u32 {
            self.process_group_id as u32
        }

        pub(super) fn wait(&mut self) -> Result<ChildExit, ProcessLaunchError> {
            let status = self.wait_for_child()?;
            wait_for_group_exit(self.process_group_id)?;
            self.settled = true;
            Ok(ChildExit {
                code: status.code().unwrap_or_default() as u32,
                signal: std::os::unix::process::ExitStatusExt::signal(&status),
            })
        }

        pub(super) fn wait_with_settlement(
            &mut self,
        ) -> Result<ChildCompletion, ProcessLaunchError> {
            let exit = self.wait()?;
            let settlement = self.settlement()?;
            Ok(ChildCompletion { exit, settlement })
        }

        pub(super) fn try_wait(&self) -> Result<Option<ChildExit>, ProcessLaunchError> {
            if self.child_reaped {
                return Ok(self.child_exit);
            }

            // `Child::try_wait` reaps an exited child. Keep the leader as a
            // waitable zombie until cleanup so its PID remains part of our
            // ownership proof and cannot be reused between lifecycle phases.
            peek_child_exit(self.process_group_id)
        }

        pub(super) fn read_output(&self) -> Result<ChildOutput, ProcessLaunchError> {
            Ok(snapshot_output(&self.stdout, &self.stderr)?)
        }

        pub(super) fn write_input(&self, bytes: &[u8]) -> Result<usize, ProcessLaunchError> {
            let mut stdin = self.stdin.lock().map_err(|_| mutex_error("write_input"))?;
            if stdin.is_none() {
                let mut child = self.child.lock().map_err(|_| mutex_error("write_input"))?;
                *stdin = child.stdin.take();
            }
            let Some(stdin) = stdin.as_mut() else {
                return Err(ProcessLaunchError::operation(
                    "write_input",
                    "owned process has no writable protocol input",
                ));
            };
            stdin
                .write_all(bytes)
                .map_err(|error| ProcessLaunchError::operation("write_input", error.to_string()))?;
            Ok(bytes.len())
        }

        pub(super) fn close_input(&mut self) {
            if let Ok(stdin) = self.stdin.get_mut() {
                stdin.take();
            }
            if let Ok(child) = self.child.get_mut() {
                child.stdin.take();
            }
        }

        pub(super) fn drain_output(&self) -> Result<ChildOutput, ProcessLaunchError> {
            self.drain_output_with(|| false)
        }

        pub(super) fn drain_output_with<F>(
            &self,
            cancelled: F,
        ) -> Result<ChildOutput, ProcessLaunchError>
        where
            F: Fn() -> bool,
        {
            let deadline = Instant::now() + DRAIN_DEADLINE;
            loop {
                let output = self.read_output()?;
                if output.stdout_closed && output.stderr_closed {
                    return Ok(output);
                }
                let cancellation_observed = cancelled();
                if cancellation_observed || Instant::now() >= deadline {
                    return Ok(ChildOutput {
                        cancellation_observed,
                        output_incomplete: true,
                        ..output
                    });
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        pub(super) fn cancel(&mut self, exit_code: u32) -> Result<(), ProcessLaunchError> {
            let result = self.cleanup(exit_code);
            if let Err(error) = &result {
                self.cleanup_failure = Some(error.clone());
            }
            result
        }

        pub(super) fn retry_cleanup(&mut self, exit_code: u32) -> Result<(), ProcessLaunchError> {
            let result = self.cleanup(exit_code);
            if result.is_ok() {
                self.cleanup_failure = None;
            } else if let Err(error) = &result {
                self.cleanup_failure = Some(error.clone());
            }
            result
        }

        pub(super) fn last_cleanup_failure(&self) -> Option<&ProcessLaunchError> {
            self.cleanup_failure.as_ref()
        }

        pub(super) fn settlement(&self) -> Result<JobSettlement, ProcessLaunchError> {
            let active_processes =
                if self.child_reaped || peek_child_exit(self.process_group_id)?.is_some() {
                    0
                } else {
                    1
                };
            Ok(JobSettlement {
                active_processes,
                peak_memory_bytes: 0,
                memory_limit_reached: false,
            })
        }

        pub(super) fn active_processes(&self) -> Result<u32, ProcessLaunchError> {
            Ok(self.settlement()?.active_processes)
        }

        fn cleanup(&mut self, _exit_code: u32) -> Result<(), ProcessLaunchError> {
            if !self.settled {
                // Group termination is authorized while the unreaped leader
                // still proves ownership. Once it has been reaped, retries
                // must only wait for settlement; signaling a bare, reusable
                // PGID would lose that proof.
                if !self.child_reaped {
                    let leader_exit_observed = peek_child_exit(self.process_group_id)?.is_some();
                    terminate_owned_group(
                        self.process_group_id,
                        &self.process_identity,
                        leader_exit_observed,
                    )?;
                    let _ = self.wait_for_child()?;
                }
            }

            wait_for_group_exit(self.process_group_id)?;
            self.settled = true;
            Ok(())
        }

        fn wait_for_child(&mut self) -> Result<std::process::ExitStatus, ProcessLaunchError> {
            if self.child_reaped {
                return self
                    .child
                    .get_mut()
                    .map_err(|_| mutex_error("wait"))?
                    .try_wait()
                    .map_err(|error| ProcessLaunchError::operation("wait", error.to_string()))?
                    .ok_or_else(|| ProcessLaunchError::operation("wait", "child status was lost"));
            }

            let status = self
                .child
                .get_mut()
                .map_err(|_| mutex_error("wait"))?
                .wait()
                .map_err(|error| ProcessLaunchError::operation("wait", error.to_string()))?;
            let exit = ChildExit {
                code: status.code().unwrap_or_default() as u32,
                signal: std::os::unix::process::ExitStatusExt::signal(&status),
            };
            self.child_exit = Some(exit);
            self.child_reaped = true;
            Ok(status)
        }
    }

    impl Drop for UnixChildProcess {
        fn drop(&mut self) {
            if !self.settled {
                let _ = self.cleanup(1);
            }
        }
    }

    fn configure_owned_process_group(command: &mut Command) -> Result<(), ProcessLaunchError> {
        // SAFETY: the closure uses only the async-signal-safe setpgid call and
        // is registered on this still-owned Command before it is spawned.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    return Ok(());
                }
                Err(std::io::Error::last_os_error())
            });
        }
        Ok(())
    }

    pub(crate) fn verify_owned_process_group(
        process_group_id: libc::pid_t,
    ) -> Result<String, ProcessLaunchError> {
        let pid = u64::try_from(process_group_id).map_err(|_| {
            ProcessLaunchError::operation("observe_process_group", "child PID must be positive")
        })?;
        match ProcessIdentityObserver.observe(pid, false) {
            Observation::Readable {
                identity,
                relation: Some(relation),
                ..
            } if relation.process_group_id == Some(pid) => Ok(identity),
            Observation::Readable { relation, .. } => Err(ProcessLaunchError::operation(
                "observe_process_group",
                format!("child process group was not confirmed: {relation:?}"),
            )),
            observation => Err(ProcessLaunchError::operation(
                "observe_process_group",
                format!("child process identity was not readable: {observation:?}"),
            )),
        }
    }

    pub(crate) fn verify_group_owner(
        process_group_id: libc::pid_t,
        process_identity: &str,
    ) -> Result<(), ProcessLaunchError> {
        let pid = u64::try_from(process_group_id).map_err(|_| {
            ProcessLaunchError::operation("verify_process_group", "process group ID is invalid")
        })?;
        match ProcessIdentityObserver.observe(pid, false) {
            Observation::Readable {
                identity,
                relation: Some(relation),
                ..
            } if identity == process_identity && relation.process_group_id == Some(pid) => Ok(()),
            observation => Err(ProcessLaunchError::operation(
                "verify_process_group",
                format!("owned process-group identity could not be confirmed: {observation:?}"),
            )),
        }
    }

    fn terminate_owned_group(
        process_group_id: libc::pid_t,
        process_identity: &str,
        leader_exit_observed: bool,
    ) -> Result<(), ProcessLaunchError> {
        if !leader_exit_observed {
            verify_group_owner(process_group_id, process_identity)?;
        }
        // SAFETY: ownership was re-verified above when the child was live, or
        // the unreaped leader still proves the process-group identity; the
        // negative pid addresses that process group only.
        let result = unsafe { libc::kill(-process_group_id, libc::SIGKILL) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        if leader_exit_observed && error.raw_os_error() == Some(libc::EPERM) {
            match group_has_live_members(process_group_id as u32) {
                Ok(false) => return Ok(()),
                Ok(true) => {}
                Err(reason) => {
                    return Err(ProcessLaunchError::operation(
                        "verify_process_group_settlement",
                        format!(
                            "group signal failed: {error}; membership verification failed: {reason}"
                        ),
                    ));
                }
            }
        }
        Err(ProcessLaunchError::operation(
            "terminate_process_group",
            error.to_string(),
        ))
    }

    /// Observe an owned child without reaping it. `Child::try_wait` cannot be
    /// used here because cleanup relies on the leader zombie to retain the
    /// process-group ownership proof until the group has settled.
    fn peek_child_exit(
        process_group_id: libc::pid_t,
    ) -> Result<Option<ChildExit>, ProcessLaunchError> {
        // SAFETY: `waitid` writes the provided siginfo value and only observes
        // this process's own unreaped child without changing its wait state.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `P_PID` addresses the owned leader, `info` is a valid
        // out-parameter, and `WNOWAIT` leaves the child available to reap.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                process_group_id as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            return Err(ProcessLaunchError::operation(
                "try_wait",
                std::io::Error::last_os_error().to_string(),
            ));
        }

        #[cfg(target_os = "linux")]
        let (child, status) = unsafe { (info.si_pid(), info.si_status()) };
        #[cfg(not(target_os = "linux"))]
        let (child, status) = (info.si_pid, info.si_status);
        if child == 0 {
            return Ok(None);
        }

        Ok(Some(if info.si_code == libc::CLD_EXITED {
            ChildExit {
                code: status as u32,
                signal: None,
            }
        } else {
            ChildExit {
                code: 0,
                signal: Some(status),
            }
        }))
    }

    pub(crate) fn wait_for_group_exit(
        process_group_id: libc::pid_t,
    ) -> Result<(), ProcessLaunchError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: kill with signal zero only probes the verified process
            // group and does not dereference memory.
            let result = unsafe { libc::kill(-process_group_id, 0) };
            let mut last_error = None;
            if result != 0 {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::ESRCH) => return Ok(()),
                    // macOS reports EPERM for a group whose remaining members
                    // are unreaped zombies (e.g. orphans awaiting launchd).
                    // That is not settlement proof; keep polling.
                    Some(libc::EPERM) => last_error = Some(error),
                    _ => {
                        return Err(ProcessLaunchError::operation(
                            "settle_process_group",
                            error.to_string(),
                        ));
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(ProcessLaunchError::operation(
                    "settle_process_group",
                    match last_error {
                        Some(error) => format!(
                            "owned process group settlement was not confirmed before cleanup deadline: {error}"
                        ),
                        None => {
                            "owned process group remained active after cleanup deadline".to_owned()
                        }
                    },
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn spawn_capture_thread<R>(
        mut reader: R,
        state: Arc<Mutex<CapturedStream>>,
        max_capture_bytes: usize,
    ) where
        R: Read + Send + 'static,
    {
        std::thread::spawn(move || {
            let mut buffer = vec![0; READ_CHUNK_SIZE];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        if let Ok(mut capture) = state.lock() {
                            let available = max_capture_bytes.saturating_sub(capture.bytes.len());
                            let retained = count.min(available);
                            capture.bytes.extend_from_slice(&buffer[..retained]);
                            capture.truncated |= retained < count;
                        } else {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            if let Ok(mut capture) = state.lock() {
                capture.closed = true;
            }
        });
    }

    fn snapshot_output(
        stdout: &Arc<Mutex<CapturedStream>>,
        stderr: &Arc<Mutex<CapturedStream>>,
    ) -> Result<ChildOutput, ProcessLaunchError> {
        let stdout = stdout.lock().map_err(|_| mutex_error("read_output"))?;
        let stderr = stderr.lock().map_err(|_| mutex_error("read_output"))?;
        Ok(ChildOutput {
            stdout: stdout.bytes.clone(),
            stderr: stderr.bytes.clone(),
            stdout_closed: stdout.closed,
            stderr_closed: stderr.closed,
            output_incomplete: stdout.truncated || stderr.truncated,
            cancellation_observed: false,
        })
    }

    fn mutex_error(operation: &'static str) -> ProcessLaunchError {
        ProcessLaunchError::operation(operation, "child process state lock was poisoned")
    }
}

#[cfg(not(windows))]
#[derive(Debug)]
pub struct OwnedChildProcess(unix::UnixChildProcess);

#[cfg(not(windows))]
impl OwnedChildProcess {
    pub fn launch(spec: ChildLaunchSpec) -> Result<Self, ProcessLaunchError> {
        unix::UnixChildProcess::launch(spec).map(Self)
    }

    /// Launch with inherited environment and an explicit per-stream capture bound.
    pub fn launch_with_capture_limit(
        spec: ChildLaunchSpec,
        max_capture_bytes: usize,
    ) -> Result<Self, ProcessLaunchError> {
        unix::UnixChildProcess::launch_bounded(spec, None, false, max_capture_bytes)
            .map(|(child, _)| Self(child))
    }

    /// Launch a long-lived protocol child with a complete explicit
    /// environment (nothing else is inherited).
    ///
    /// Stdout is returned unread so the protocol owner can frame it
    /// incrementally without a cumulative capture bound; stderr stays
    /// captured (bounded) by this owner. Ownership of the process group,
    /// cancellation and settlement are unchanged.
    pub fn launch_protocol(
        spec: ChildLaunchSpec,
        environment: &[(OsString, OsString)],
    ) -> Result<(Self, std::process::ChildStdout), ProcessLaunchError> {
        let (child, stdout) = unix::UnixChildProcess::launch_with(spec, Some(environment), true)?;
        let stdout = stdout.ok_or_else(|| {
            ProcessLaunchError::operation("capture_stdout", "child stdout was not streamed")
        })?;
        Ok((Self(child), stdout))
    }

    /// Launch with a complete explicit environment (nothing else is
    /// inherited) and an explicit per-stream capture bound. Output beyond the
    /// bound sets `ChildOutput::output_incomplete`.
    pub fn launch_with_environment(
        spec: ChildLaunchSpec,
        environment: &[(OsString, OsString)],
        max_capture_bytes: usize,
    ) -> Result<Self, ProcessLaunchError> {
        unix::UnixChildProcess::launch_bounded(spec, Some(environment), false, max_capture_bytes)
            .map(|(child, _)| Self(child))
    }

    /// Deliver a POSIX stop signal to the owned process group after
    /// re-verifying ownership. `cancel` remains the SIGKILL-and-settle path.
    pub fn signal(&self, signal: i32) -> Result<(), ProcessLaunchError> {
        self.0.signal_group(signal)
    }

    /// The owned child PID (also its process-group ID).
    pub fn id(&self) -> u32 {
        self.0.id()
    }

    pub fn wait(&mut self) -> Result<ChildExit, ProcessLaunchError> {
        self.0.wait()
    }
    pub fn wait_with_settlement(&mut self) -> Result<ChildCompletion, ProcessLaunchError> {
        self.0.wait_with_settlement()
    }
    pub fn try_wait(&self) -> Result<Option<ChildExit>, ProcessLaunchError> {
        self.0.try_wait()
    }
    pub fn read_output(&self) -> Result<ChildOutput, ProcessLaunchError> {
        self.0.read_output()
    }
    pub fn write_input(&self, bytes: &[u8]) -> Result<usize, ProcessLaunchError> {
        self.0.write_input(bytes)
    }
    pub fn close_input(&mut self) {
        self.0.close_input();
    }
    pub fn drain_output(&self) -> Result<ChildOutput, ProcessLaunchError> {
        self.0.drain_output()
    }
    pub fn drain_output_with<F>(&self, cancelled: F) -> Result<ChildOutput, ProcessLaunchError>
    where
        F: Fn() -> bool,
    {
        self.0.drain_output_with(cancelled)
    }
    pub fn cancel(&mut self, exit_code: u32) -> Result<(), ProcessLaunchError> {
        self.0.cancel(exit_code)
    }
    pub fn retry_cleanup(&mut self, exit_code: u32) -> Result<(), ProcessLaunchError> {
        self.0.retry_cleanup(exit_code)
    }
    pub fn last_cleanup_failure(&self) -> Option<&ProcessLaunchError> {
        self.0.last_cleanup_failure()
    }
    pub fn settlement(&self) -> Result<JobSettlement, ProcessLaunchError> {
        self.0.settlement()
    }
    pub fn active_processes(&self) -> Result<u32, ProcessLaunchError> {
        self.0.active_processes()
    }
}

#[cfg(windows)]
mod windows {
    const MAX_READ_PER_POLL: usize = 1024 * 1024;
    const READ_CHUNK_SIZE: usize = 64 * 1024;
    const INPUT_WRITE_CHUNK_SIZE: usize = 64 * 1024;
    const CLEANUP_DEADLINE_MILLISECONDS: u32 = 5_000;

    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle as KernelHandle};
    use std::path::Path;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
    use std::time::{Duration, Instant};

    const INPUT_WRITE_TIMEOUT_MILLISECONDS: u32 = 1_000;
    static INPUT_PIPE_SEQUENCE: AtomicU32 = AtomicU32::new(1);

    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NOT_FOUND,
            ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, GENERIC_WRITE, GetLastError, HANDLE,
            HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0,
            WAIT_TIMEOUT,
        },
        Security::{
            GetTokenInformation, SECURITY_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT,
            TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenOwner, TokenUser,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE,
            FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_INBOUND, ReadFile, WriteFile,
        },
        System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        System::JobObjects::IsProcessInJob,
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, CreatePipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
            PIPE_WAIT, PeekNamedPipe,
        },
        System::Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateEventW,
            CreateProcessW, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess,
            GetPriorityClass, GetProcessAffinityMask, GetProcessGroupAffinity, GetProcessId,
            OpenProcessToken, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW, SetPriorityClass,
            SetProcessAffinityMask, TerminateProcess, WaitForSingleObject,
        },
    };

    use super::{
        ChildCompletion, ChildExit, ChildLaunchSpec, ChildOutput, JobSettlement, ProcessLaunchError,
    };
    use crate::process::windows::resources::WindowsOwnedResources;

    struct OwnedHandle(KernelHandle);

    impl OwnedHandle {
        fn new(handle: HANDLE) -> Result<Self, ProcessLaunchError> {
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(ProcessLaunchError::operation(
                    "handle",
                    format!("Windows handle creation failed: {}", unsafe {
                        GetLastError()
                    }),
                ));
            }

            // Each successful creation transfers its unique handle here.
            Ok(Self(unsafe { KernelHandle::from_raw_handle(handle) }))
        }

        fn raw(&self) -> HANDLE {
            self.0.as_raw_handle()
        }
    }

    struct WindowsInput {
        handle: OwnedHandle,
        cancel_requested: AtomicBool,
        write_lock: Mutex<()>,
    }

    #[derive(Clone)]
    pub(super) struct WindowsInputWriter {
        input: Arc<WindowsInput>,
    }

    impl WindowsInput {
        fn new(handle: OwnedHandle) -> Self {
            Self {
                handle,
                cancel_requested: AtomicBool::new(false),
                write_lock: Mutex::new(()),
            }
        }

        fn writer(self: &Arc<Self>) -> WindowsInputWriter {
            WindowsInputWriter {
                input: Arc::clone(self),
            }
        }

        fn cancel_pending(&self) -> Result<(), ProcessLaunchError> {
            self.cancel_requested.store(true, Ordering::SeqCst);
            let cancelled = unsafe { CancelIoEx(self.handle.raw(), ptr::null_mut()) };
            if cancelled != 0 {
                return Ok(());
            }

            let error = unsafe { GetLastError() };
            if error == ERROR_NOT_FOUND {
                return Ok(());
            }
            Err(ProcessLaunchError::operation(
                "cancel_write",
                format!("CancelIoEx failed: {error}"),
            ))
        }

        fn write_frame(
            &self,
            bytes: &[u8],
            timeout_milliseconds: u32,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<usize, ProcessLaunchError> {
            let deadline = Instant::now() + Duration::from_millis(timeout_milliseconds as u64);
            let _write_guard = self.acquire_frame(deadline, cancelled)?;
            let mut written = 0usize;

            while written < bytes.len() {
                self.check_interruption(deadline, cancelled)?;
                let count = self.write_chunk(&bytes[written..], deadline, cancelled)?;
                if count == 0 {
                    return Err(ProcessLaunchError::operation(
                        "write_input",
                        "WriteFile made no progress",
                    ));
                }
                written += count as usize;
            }

            Ok(written)
        }

        fn acquire_frame(
            &self,
            deadline: Instant,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<MutexGuard<'_, ()>, ProcessLaunchError> {
            loop {
                self.check_interruption(deadline, cancelled)?;
                match self.write_lock.try_lock() {
                    Ok(guard) => return Ok(guard),
                    Err(TryLockError::Poisoned(error)) => return Ok(error.into_inner()),
                    Err(TryLockError::WouldBlock) => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        }

        fn check_interruption(
            &self,
            deadline: Instant,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<(), ProcessLaunchError> {
            if self.cancel_requested.load(Ordering::SeqCst) || cancelled() {
                return Err(cancelled_write_error());
            }
            if Instant::now() >= deadline {
                return Err(timed_out_write_error());
            }
            Ok(())
        }

        fn write_chunk(
            &self,
            bytes: &[u8],
            deadline: Instant,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u32, ProcessLaunchError> {
            let requested = bytes.len().min(INPUT_WRITE_CHUNK_SIZE) as u32;
            let event = OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            overlapped.hEvent = event.raw();

            let started = unsafe {
                WriteFile(
                    self.handle.raw(),
                    bytes.as_ptr().cast(),
                    requested,
                    ptr::null_mut(),
                    &mut overlapped,
                )
            };
            if started == 0 {
                let error = unsafe { GetLastError() };
                if error != ERROR_IO_PENDING {
                    return Err(ProcessLaunchError::operation(
                        "write_input",
                        format!("WriteFile failed: {error}"),
                    ));
                }
            }

            self.wait_for_write_completion(&mut overlapped, event.raw(), deadline, cancelled)
        }

        fn wait_for_write_completion(
            &self,
            overlapped: &mut OVERLAPPED,
            event: HANDLE,
            deadline: Instant,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u32, ProcessLaunchError> {
            loop {
                if let Err(error) = self.check_interruption(deadline, cancelled) {
                    return Err(attach_cleanup(
                        error,
                        self.cancel_overlapped_and_wait(overlapped)
                            .err()
                            .map(|cleanup| cleanup.to_string()),
                    ));
                }

                let remaining = deadline.saturating_duration_since(Instant::now());
                let wait_milliseconds =
                    remaining.min(Duration::from_millis(25)).as_millis().max(1) as u32;
                let wait = unsafe { WaitForSingleObject(event, wait_milliseconds) };
                if wait == WAIT_TIMEOUT {
                    continue;
                }
                if wait != WAIT_OBJECT_0 {
                    let error = ProcessLaunchError::operation(
                        "write_input",
                        format!("waiting for WriteFile failed: {wait}"),
                    );
                    return Err(attach_cleanup(
                        error,
                        self.cancel_overlapped_and_wait(overlapped)
                            .err()
                            .map(|cleanup| cleanup.to_string()),
                    ));
                }

                return completion_count(self.handle.raw(), overlapped);
            }
        }

        fn cancel_overlapped_and_wait(
            &self,
            overlapped: &mut OVERLAPPED,
        ) -> Result<(), ProcessLaunchError> {
            let cancellation_error = if unsafe { CancelIoEx(self.handle.raw(), overlapped) } == 0 {
                let error = unsafe { GetLastError() };
                (error != ERROR_NOT_FOUND).then(|| {
                    ProcessLaunchError::operation(
                        "cancel_write",
                        format!("CancelIoEx failed: {error}"),
                    )
                })
            } else {
                None
            };

            let mut count = 0u32;
            let completed = unsafe {
                // The blocking flag is deliberate: the OVERLAPPED storage
                // remains live until the kernel has completed cancellation.
                GetOverlappedResult(self.handle.raw(), overlapped, &mut count, 1)
            };
            if completed == 0 {
                let error = unsafe { GetLastError() };
                if error != ERROR_OPERATION_ABORTED {
                    let completion_error = ProcessLaunchError::operation(
                        "cancel_write",
                        format!("GetOverlappedResult failed after cancellation: {error}"),
                    );
                    return Err(match cancellation_error {
                        Some(cancellation_error) => {
                            cancellation_error.with_cleanup(completion_error.to_string())
                        }
                        None => completion_error,
                    });
                }
            }

            if let Some(cancellation_error) = cancellation_error {
                return Err(cancellation_error);
            }
            Ok(())
        }
    }

    impl WindowsInputWriter {
        pub(super) fn write_input_with_timeout(
            &self,
            bytes: &[u8],
            timeout_milliseconds: u32,
        ) -> Result<usize, ProcessLaunchError> {
            self.input
                .write_frame(bytes, timeout_milliseconds, &|| false)
        }

        pub(super) fn write_input_with_timeout_and_cancel(
            &self,
            bytes: &[u8],
            timeout_milliseconds: u32,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<usize, ProcessLaunchError> {
            self.input
                .write_frame(bytes, timeout_milliseconds, cancelled)
        }
    }

    fn cancelled_write_error() -> ProcessLaunchError {
        ProcessLaunchError::operation("write_input", "protocol input write was cancelled")
    }

    fn timed_out_write_error() -> ProcessLaunchError {
        ProcessLaunchError::operation("write_input", "protocol input write timed out")
    }

    fn completion_count(
        handle: HANDLE,
        overlapped: &mut OVERLAPPED,
    ) -> Result<u32, ProcessLaunchError> {
        let mut count = 0u32;
        if unsafe { GetOverlappedResult(handle, overlapped, &mut count, 1) } == 0 {
            return Err(ProcessLaunchError::operation(
                "write_input",
                format!("WriteFile completion failed: {}", unsafe { GetLastError() }),
            ));
        }
        Ok(count)
    }

    pub(super) struct WindowsChildProcess {
        process: OwnedHandle,
        stdin: Option<Arc<WindowsInput>>,
        stdout: OwnedHandle,
        stderr: OwnedHandle,
        job: WindowsOwnedResources,
        max_capture_bytes: usize,
        settled: bool,
        cleanup_failure: Option<ProcessLaunchError>,
    }

    trait CleanupExecutor {
        fn terminate_for_cleanup(&mut self, exit_code: u32) -> Result<(), ProcessLaunchError>;
        fn wait_for_cleanup(&mut self) -> Result<(), ProcessLaunchError>;
        fn settle_for_cleanup(&mut self) -> Result<(), ProcessLaunchError>;
    }

    fn attempt_cleanup(
        executor: &mut impl CleanupExecutor,
        exit_code: u32,
    ) -> Result<(), ProcessLaunchError> {
        let mut failure = executor.terminate_for_cleanup(exit_code).err();

        if let Err(error) = executor.wait_for_cleanup() {
            failure = Some(merge_cleanup_failure(failure, error));
        }

        if let Err(error) = executor.settle_for_cleanup() {
            failure = Some(merge_cleanup_failure(failure, error));
        }

        failure.map_or(Ok(()), Err)
    }

    fn merge_cleanup_failure(
        primary: Option<ProcessLaunchError>,
        cleanup: ProcessLaunchError,
    ) -> ProcessLaunchError {
        match primary {
            Some(primary) => primary.with_cleanup(cleanup.to_string()),
            None => cleanup,
        }
    }

    impl WindowsChildProcess {
        fn launch_with_capture_limit(
            spec: ChildLaunchSpec,
            max_capture_bytes: usize,
            environment: Option<&[(std::ffi::OsString, std::ffi::OsString)]>,
        ) -> Result<Self, ProcessLaunchError> {
            validate_executable_path(&spec.executable)?;

            let job = WindowsOwnedResources::create_from_job_limits(spec.limits)
                .map_err(|message| ProcessLaunchError::operation("create_job", message))?;

            let mut command_line = command_line_wide(&spec.executable, &spec.arguments);
            let executable = wide_null(&spec.executable.to_string_lossy());
            let working_directory = spec
                .working_directory
                .as_ref()
                .map(|path| wide_null(&path.to_string_lossy()));
            let working_directory_pointer = working_directory
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr());
            let environment = environment.map(environment_block).transpose()?;
            let environment_pointer = environment
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr().cast());
            let (stdout, stdout_write) = create_pipe()?;
            let (stderr, stderr_write) = create_pipe()?;
            let (stdin_read, stdin_write) = create_input_pipe()?;
            let stdin_write = spec
                .protocol_stdin
                .then(|| Arc::new(WindowsInput::new(stdin_write)));
            let mut startup = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: stdin_read.raw(),
                hStdOutput: stdout_write.raw(),
                hStdError: stderr_write.raw(),
                ..unsafe { std::mem::zeroed() }
            };
            let mut process_info = std::mem::MaybeUninit::zeroed();
            let created = unsafe {
                CreateProcessW(
                    executable.as_ptr(),
                    command_line.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    1,
                    owned_process_creation_flags(),
                    environment_pointer,
                    working_directory_pointer,
                    &mut startup,
                    process_info.as_mut_ptr(),
                )
            };
            if created == 0 {
                return Err(ProcessLaunchError::operation(
                    "create_process",
                    format!("CreateProcessW failed: {}", unsafe { GetLastError() }),
                ));
            }

            let process_info = unsafe { process_info.assume_init() };
            let process = OwnedHandle::new(process_info.hProcess).map_err(|error| {
                close_unowned_thread(process_info.hThread);
                error
            })?;
            let thread = OwnedHandle::new(process_info.hThread).map_err(|error| {
                terminate_unassigned_process(process.raw());
                error
            })?;

            if let Err(message) = job.assign_child(process.raw()) {
                let cleanup = terminate_and_wait(process.raw());
                drop(thread);
                return Err(attach_cleanup(
                    ProcessLaunchError::operation("assign_job", message),
                    cleanup,
                ));
            }

            if !is_member(process.raw(), job.raw_handle()) {
                let cleanup = terminate_owned_job_and_wait(&job, process.raw());
                drop(thread);
                return Err(attach_cleanup(
                    ProcessLaunchError::operation(
                        "verify_job_membership",
                        "suspended child is not a member of its owned Job Object",
                    ),
                    cleanup,
                ));
            }

            if let Err(message) = normalize_child_token_owner(process.raw()) {
                let cleanup = terminate_owned_job_and_wait(&job, process.raw());
                drop(thread);
                return Err(attach_cleanup(
                    ProcessLaunchError::operation("normalize_process_owner", message),
                    cleanup,
                ));
            }

            if let Err(message) = preserve_caller_priority(process.raw()) {
                let cleanup = terminate_owned_job_and_wait(&job, process.raw());
                drop(thread);
                return Err(attach_cleanup(
                    ProcessLaunchError::operation("preserve_process_priority", message),
                    cleanup,
                ));
            }

            if let Err(message) = preserve_caller_affinity(process.raw()) {
                let cleanup = terminate_owned_job_and_wait(&job, process.raw());
                drop(thread);
                return Err(attach_cleanup(
                    ProcessLaunchError::operation("preserve_process_affinity", message),
                    cleanup,
                ));
            }

            if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
                let cleanup = terminate_owned_job_and_wait(&job, process.raw());
                drop(thread);
                return Err(attach_cleanup(
                    ProcessLaunchError::operation(
                        "resume_process",
                        format!("ResumeThread failed: {}", unsafe { GetLastError() }),
                    ),
                    cleanup,
                ));
            }

            drop(thread);
            drop(stdin_read);
            drop(stdout_write);
            drop(stderr_write);
            Ok(Self {
                process,
                stdin: stdin_write,
                stdout,
                stderr,
                job,
                max_capture_bytes,
                settled: false,
                cleanup_failure: None,
            })
        }

        fn wait(&mut self) -> Result<ChildExit, ProcessLaunchError> {
            let wait = unsafe { WaitForSingleObject(self.process.raw(), u32::MAX) };
            if wait != WAIT_OBJECT_0 {
                return Err(ProcessLaunchError::operation(
                    "wait",
                    format!("WaitForSingleObject returned {}", wait),
                ));
            }

            let exit = read_exit_code(self.process.raw())?;
            self.settle()?;
            Ok(exit)
        }

        fn wait_with_settlement(&mut self) -> Result<ChildCompletion, ProcessLaunchError> {
            let exit = self.wait()?;
            let settlement = self.settlement()?;
            Ok(ChildCompletion { exit, settlement })
        }

        fn try_wait(&self) -> Result<Option<ChildExit>, ProcessLaunchError> {
            self.job.observe_memory_limit().map_err(|message| {
                ProcessLaunchError::operation("observe_job_notifications", message)
            })?;

            let wait = unsafe { WaitForSingleObject(self.process.raw(), 0) };
            if wait == WAIT_TIMEOUT {
                return Ok(None);
            }
            if wait != WAIT_OBJECT_0 {
                return Err(ProcessLaunchError::operation(
                    "try_wait",
                    format!("WaitForSingleObject returned {wait}"),
                ));
            }

            self.job.observe_memory_limit().map_err(|message| {
                ProcessLaunchError::operation("observe_job_notifications", message)
            })?;

            read_exit_code(self.process.raw()).map(Some)
        }

        fn read_output(&self) -> Result<ChildOutput, ProcessLaunchError> {
            let stdout = read_pipe(self.stdout.raw(), self.max_capture_bytes)?;
            let stderr = read_pipe(self.stderr.raw(), self.max_capture_bytes)?;
            Ok(ChildOutput {
                stdout: stdout.bytes,
                stderr: stderr.bytes,
                stdout_closed: stdout.closed,
                stderr_closed: stderr.closed,
                output_incomplete: stdout.truncated || stderr.truncated,
                cancellation_observed: false,
            })
        }

        pub(super) fn input_writer(&self) -> Option<WindowsInputWriter> {
            self.stdin.as_ref().map(WindowsInput::writer)
        }

        fn write_input_with_timeout(
            &self,
            bytes: &[u8],
            timeout_milliseconds: u32,
        ) -> Result<usize, ProcessLaunchError> {
            let Some(stdin) = self.stdin.as_ref() else {
                return Err(ProcessLaunchError::operation(
                    "write_input",
                    "owned process has no writable protocol input",
                ));
            };

            stdin.write_frame(bytes, timeout_milliseconds, &|| false)
        }

        fn close_input(&mut self) {
            self.stdin.take();
        }

        fn drain_output_with<F>(&self, cancelled: F) -> Result<ChildOutput, ProcessLaunchError>
        where
            F: Fn() -> bool,
        {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
            let mut output = ChildOutput::default();
            while std::time::Instant::now() < deadline {
                let chunk = self.read_output()?;
                let stdout_truncated =
                    append_with_limit(&mut output.stdout, chunk.stdout, self.max_capture_bytes);
                let stderr_truncated =
                    append_with_limit(&mut output.stderr, chunk.stderr, self.max_capture_bytes);
                output.stdout_closed |= chunk.stdout_closed;
                output.stderr_closed |= chunk.stderr_closed;
                output.output_incomplete |=
                    chunk.output_incomplete || stdout_truncated || stderr_truncated;
                if cancelled() {
                    output.cancellation_observed = true;
                    output.output_incomplete = !(output.stdout_closed && output.stderr_closed);
                    return Ok(output);
                }
                if output.stdout_closed && output.stderr_closed {
                    return Ok(output);
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            output.output_incomplete = !(output.stdout_closed && output.stderr_closed);
            Ok(output)
        }

        fn cancel(&mut self, exit_code: u32) -> Result<(), ProcessLaunchError> {
            let result = self.cleanup_owned_process(exit_code);
            if let Err(error) = &result {
                self.remember_cleanup_failure(error);
            }
            result
        }

        fn retry_cleanup(&mut self, exit_code: u32) -> Result<(), ProcessLaunchError> {
            let result = self.cleanup_owned_process(exit_code);
            if result.is_ok() {
                self.cleanup_failure = None;
            }
            if let Err(error) = &result {
                self.remember_cleanup_failure(error);
            }
            result
        }

        fn cleanup_owned_process(&mut self, exit_code: u32) -> Result<(), ProcessLaunchError> {
            attempt_cleanup(self, exit_code)
        }

        fn wait_for_settlement(&mut self) -> Result<(), ProcessLaunchError> {
            let wait =
                unsafe { WaitForSingleObject(self.process.raw(), CLEANUP_DEADLINE_MILLISECONDS) };
            if wait == WAIT_TIMEOUT {
                let error = ProcessLaunchError::operation(
                    "wait_after_cancel",
                    "owned process did not settle before the cleanup deadline",
                );
                self.remember_cleanup_failure(&error);
                return Err(error);
            }
            if wait != WAIT_OBJECT_0 {
                let error = ProcessLaunchError::operation(
                    "wait_after_cancel",
                    format!("WaitForSingleObject returned {}", wait),
                );
                self.remember_cleanup_failure(&error);
                return Err(error);
            }

            Ok(())
        }

        fn settle(&mut self) -> Result<(), ProcessLaunchError> {
            let result = self.settle_inner();
            if let Err(error) = &result {
                self.remember_cleanup_failure(error);
            }
            result
        }

        fn settle_inner(&mut self) -> Result<(), ProcessLaunchError> {
            let active_processes = self
                .job
                .active_processes()
                .map_err(|message| ProcessLaunchError::operation("settle_job", message))?;
            if active_processes != 0 {
                return Err(ProcessLaunchError::operation(
                    "settle_job",
                    format!("owned Job Object still has {active_processes} active process(es)"),
                ));
            }

            self.settled = true;
            Ok(())
        }

        fn remember_cleanup_failure(&mut self, error: &ProcessLaunchError) {
            self.cleanup_failure = Some(error.clone());
        }

        fn last_cleanup_failure(&self) -> Option<&ProcessLaunchError> {
            self.cleanup_failure.as_ref()
        }

        fn settlement(&self) -> Result<JobSettlement, ProcessLaunchError> {
            let active_processes = self
                .job
                .active_processes()
                .map_err(|message| ProcessLaunchError::operation("observe_job", message))?;
            let peak_memory_bytes = self
                .job
                .peak_memory_bytes()
                .map_err(|message| ProcessLaunchError::operation("observe_job_memory", message))?;
            let memory_limit_reached = self.job.observe_memory_limit().map_err(|message| {
                ProcessLaunchError::operation("observe_job_notifications", message)
            })?;
            Ok(JobSettlement {
                active_processes,
                peak_memory_bytes,
                memory_limit_reached,
            })
        }

        fn active_processes(&self) -> Result<u32, ProcessLaunchError> {
            self.job.active_processes().map_err(|message| {
                ProcessLaunchError::operation("observe_active_processes", message)
            })
        }
    }

    impl CleanupExecutor for WindowsChildProcess {
        fn terminate_for_cleanup(&mut self, exit_code: u32) -> Result<(), ProcessLaunchError> {
            let input_failure = self
                .stdin
                .as_ref()
                .and_then(|stdin| stdin.cancel_pending().err());
            let termination = self
                .job
                .terminate_if_active(exit_code)
                .map(|_| ())
                .map_err(|message| ProcessLaunchError::operation("terminate_job", message));

            match (input_failure, termination) {
                (None, result) => result,
                (Some(input_failure), Ok(())) => Err(input_failure),
                (Some(input_failure), Err(termination_failure)) => {
                    Err(input_failure.with_cleanup(termination_failure.to_string()))
                }
            }
        }

        fn wait_for_cleanup(&mut self) -> Result<(), ProcessLaunchError> {
            self.wait_for_settlement()
        }

        fn settle_for_cleanup(&mut self) -> Result<(), ProcessLaunchError> {
            self.settle()
        }
    }

    impl Drop for WindowsChildProcess {
        fn drop(&mut self) {
            if self.settled {
                return;
            }

            // The explicit cancel/retry path retains this owner after a failed
            // cleanup. Drop is only a last-resort containment measure when a
            // caller abandons an unsettled child without retrying.
            let _ = self.cleanup_owned_process(1);
        }
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Build a NUL-terminated CreateProcess command line whose MSVCRT parse
    /// reproduces the executable followed by exactly `arguments`.
    pub(super) fn command_line_wide(
        executable: &Path,
        arguments: &[std::ffi::OsString],
    ) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        let mut line = Vec::new();
        // argv[0] uses simpler parsing rules and cannot contain a quote.
        line.push(u16::from(b'"'));
        line.extend(executable.as_os_str().encode_wide());
        line.push(u16::from(b'"'));
        for argument in arguments {
            line.push(u16::from(b' '));
            let units = argument.encode_wide().collect::<Vec<_>>();
            append_quoted_argument(&mut line, &units);
        }
        line.push(0);
        line
    }

    fn append_quoted_argument(line: &mut Vec<u16>, argument: &[u16]) {
        let quote = u16::from(b'"');
        let backslash = u16::from(b'\\');
        let needs_quotes = argument.is_empty()
            || argument
                .iter()
                .any(|unit| matches!(*unit, 0x20 | 0x09 | 0x0a | 0x0b | 0x22));
        if !needs_quotes {
            line.extend_from_slice(argument);
            return;
        }
        line.push(quote);
        let mut pending_backslashes = 0usize;
        for &unit in argument {
            if unit == backslash {
                pending_backslashes += 1;
                continue;
            }
            if unit == quote {
                // Escape every preceding backslash and the quote itself.
                line.extend(std::iter::repeat_n(backslash, pending_backslashes * 2 + 1));
            } else {
                line.extend(std::iter::repeat_n(backslash, pending_backslashes));
            }
            pending_backslashes = 0;
            line.push(unit);
        }
        // Backslashes before the closing quote must be doubled.
        line.extend(std::iter::repeat_n(backslash, pending_backslashes * 2));
        line.push(quote);
    }

    pub(super) fn validate_executable_path(path: &Path) -> Result<(), ProcessLaunchError> {
        if path.is_absolute() {
            return Ok(());
        }

        Err(ProcessLaunchError::operation(
            "validate_executable",
            "owned Windows process requires an absolute executable path",
        ))
    }

    pub(super) fn owned_process_creation_flags() -> u32 {
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW
    }

    pub(super) fn normalize_child_token_owner(process: HANDLE) -> Result<(), String> {
        let mut token = ptr::null_mut();
        let opened =
            unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &mut token) }
                != 0;
        if !opened {
            return Err(format!("OpenProcessToken failed: {}", unsafe {
                GetLastError()
            }));
        }
        let token = OwnedHandle::new(token).map_err(|error| error.to_string())?;

        let mut required_bytes = 0u32;
        let _ = unsafe {
            GetTokenInformation(
                token.raw(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut required_bytes,
            )
        };
        if required_bytes == 0 {
            return Err(format!(
                "GetTokenInformation size query failed: {}",
                unsafe { GetLastError() }
            ));
        }

        let word_count = (required_bytes as usize).div_ceil(std::mem::size_of::<usize>());
        let mut token_user_storage = vec![0usize; word_count];
        let read = unsafe {
            GetTokenInformation(
                token.raw(),
                TokenUser,
                token_user_storage.as_mut_ptr().cast(),
                required_bytes,
                &mut required_bytes,
            )
        } != 0;
        if !read {
            return Err(format!("GetTokenInformation failed: {}", unsafe {
                GetLastError()
            }));
        }

        let token_user = unsafe { token_user_storage.as_ptr().cast::<TOKEN_USER>().read() };
        let owner = TOKEN_OWNER {
            Owner: token_user.User.Sid,
        };
        let updated = unsafe {
            SetTokenInformation(
                token.raw(),
                TokenOwner,
                (&owner as *const TOKEN_OWNER).cast(),
                std::mem::size_of::<TOKEN_OWNER>() as u32,
            )
        } != 0;
        if !updated {
            return Err(format!(
                "SetTokenInformation(TokenOwner) failed: {}",
                unsafe { GetLastError() }
            ));
        }

        Ok(())
    }

    pub(super) fn preserve_caller_priority(process: HANDLE) -> Result<(), String> {
        let caller = unsafe { GetCurrentProcess() };
        let priority = unsafe { GetPriorityClass(caller) };
        if priority == 0 {
            return Err(format!("GetPriorityClass failed: {}", unsafe {
                GetLastError()
            }));
        }

        let applied = unsafe { SetPriorityClass(process, priority) } != 0;
        if !applied {
            return Err(format!("SetPriorityClass failed: {}", unsafe {
                GetLastError()
            }));
        }

        Ok(())
    }

    fn preserve_caller_affinity(process: HANDLE) -> Result<(), String> {
        let caller = unsafe { GetCurrentProcess() };
        let mut caller_affinity = 0usize;
        let mut system_affinity = 0usize;
        let affinity_read =
            unsafe { GetProcessAffinityMask(caller, &mut caller_affinity, &mut system_affinity) }
                != 0;
        if !affinity_read {
            return Err(format!("GetProcessAffinityMask failed: {}", unsafe {
                GetLastError()
            }));
        }

        let apply_affinity = affinity_action(
            caller_affinity,
            system_affinity,
            process_group(caller),
            process_group(process),
        )?;
        if !apply_affinity {
            return Ok(());
        }

        if unsafe { SetProcessAffinityMask(process, caller_affinity) } == 0 {
            return Err(format!("SetProcessAffinityMask failed: {}", unsafe {
                GetLastError()
            }));
        }

        Ok(())
    }

    fn process_group(process: HANDLE) -> Option<u16> {
        let mut count = 1u16;
        let mut groups = [0u16; 1];
        let read =
            unsafe { GetProcessGroupAffinity(process, &mut count, groups.as_mut_ptr()) } != 0;
        (read && count == 1).then_some(groups[0])
    }

    pub(super) fn affinity_action(
        caller_affinity: usize,
        system_affinity: usize,
        caller_group: Option<u16>,
        child_group: Option<u16>,
    ) -> Result<bool, String> {
        if caller_affinity != 0
            && caller_group
                .zip(child_group)
                .is_some_and(|(left, right)| left == right)
        {
            return Ok(true);
        }
        if caller_affinity == system_affinity {
            return Ok(false);
        }
        Err("caller CPU affinity cannot bound an owned process in another processor group".into())
    }

    fn create_pipe() -> Result<(OwnedHandle, OwnedHandle), ProcessLaunchError> {
        let mut security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: 1,
            lpSecurityDescriptor: ptr::null_mut(),
        };
        let mut read = ptr::null_mut();
        let mut write = ptr::null_mut();
        if unsafe { CreatePipe(&mut read, &mut write, &mut security, 0) } == 0 {
            return Err(ProcessLaunchError::operation(
                "create_output_pipe",
                format!("CreatePipe failed: {}", unsafe { GetLastError() }),
            ));
        }
        let read = OwnedHandle::new(read)?;
        let write = OwnedHandle::new(write)?;
        if unsafe { SetHandleInformation(read.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(ProcessLaunchError::operation(
                "protect_output_pipe",
                format!("SetHandleInformation failed: {}", unsafe { GetLastError() }),
            ));
        }
        Ok((read, write))
    }

    fn create_input_pipe() -> Result<(OwnedHandle, OwnedHandle), ProcessLaunchError> {
        let mut security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: 1,
            lpSecurityDescriptor: ptr::null_mut(),
        };
        let sequence = INPUT_PIPE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = wide_null(&format!(r"\\.\pipe\rea-ghidra-{}-{sequence}", unsafe {
            GetCurrentProcessId()
        }));
        let read = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                64 * 1024,
                64 * 1024,
                0,
                &mut security,
            )
        };
        if read == INVALID_HANDLE_VALUE {
            return Err(ProcessLaunchError::operation(
                "create_input_pipe",
                format!("CreateNamedPipeW failed: {}", unsafe { GetLastError() }),
            ));
        }
        let read = OwnedHandle::new(read)?;
        let write = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        if write == INVALID_HANDLE_VALUE {
            return Err(ProcessLaunchError::operation(
                "create_input_pipe",
                format!("CreateFileW failed: {}", unsafe { GetLastError() }),
            ));
        }
        let write = OwnedHandle::new(write)?;
        let connected = unsafe { ConnectNamedPipe(read.raw(), ptr::null_mut()) };
        if connected == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            return Err(ProcessLaunchError::operation(
                "connect_input_pipe",
                format!("ConnectNamedPipe failed: {}", unsafe { GetLastError() }),
            ));
        }
        if unsafe { SetHandleInformation(write.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(ProcessLaunchError::operation(
                "protect_input_pipe",
                format!("SetHandleInformation failed: {}", unsafe { GetLastError() }),
            ));
        }
        Ok((read, write))
    }

    struct PipeRead {
        bytes: Vec<u8>,
        closed: bool,
        truncated: bool,
    }

    pub(super) fn requested_read_size(available: u32, already_read: usize) -> u32 {
        let remaining = MAX_READ_PER_POLL.saturating_sub(already_read);
        (available as usize).min(READ_CHUNK_SIZE).min(remaining) as u32
    }

    fn read_pipe(handle: HANDLE, max_capture_bytes: usize) -> Result<PipeRead, ProcessLaunchError> {
        let mut output = Vec::new();
        let capture_limit = max_capture_bytes;
        if capture_limit == 0 {
            return Ok(PipeRead {
                bytes: output,
                closed: false,
                truncated: true,
            });
        }
        loop {
            let mut available = 0;
            if unsafe {
                PeekNamedPipe(
                    handle,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    &mut available,
                    ptr::null_mut(),
                )
            } == 0
            {
                let error = unsafe { GetLastError() };
                if error == ERROR_BROKEN_PIPE {
                    return Ok(PipeRead {
                        bytes: output,
                        closed: true,
                        truncated: false,
                    });
                }
                return Err(ProcessLaunchError::operation(
                    "read_output",
                    format!("PeekNamedPipe failed: {error}"),
                ));
            }
            if available == 0 || output.len() >= capture_limit {
                break;
            }
            let requested = requested_read_size(available, output.len())
                .min(capture_limit.saturating_sub(output.len()) as u32);
            if requested == 0 {
                break;
            }
            let mut chunk = vec![0; requested as usize];
            let mut count = 0;
            if unsafe {
                ReadFile(
                    handle,
                    chunk.as_mut_ptr().cast(),
                    requested,
                    &mut count,
                    ptr::null_mut(),
                )
            } == 0
            {
                let error = unsafe { GetLastError() };
                if error == ERROR_BROKEN_PIPE {
                    return Ok(PipeRead {
                        bytes: output,
                        closed: true,
                        truncated: false,
                    });
                }
                return Err(ProcessLaunchError::operation(
                    "read_output",
                    format!("ReadFile failed: {error}"),
                ));
            }
            output.extend_from_slice(&chunk[..count as usize]);
        }
        let truncated = output.len() >= capture_limit;
        Ok(PipeRead {
            bytes: output,
            closed: false,
            truncated,
        })
    }

    fn append_with_limit(target: &mut Vec<u8>, bytes: Vec<u8>, limit: usize) -> bool {
        let available = limit.saturating_sub(target.len());
        let retained = bytes.len().min(available);
        target.extend_from_slice(&bytes[..retained]);
        retained < bytes.len()
    }

    fn close_unowned_thread(thread: HANDLE) {
        if !thread.is_null() {
            unsafe { CloseHandle(thread) };
        }
    }

    fn terminate_unassigned_process(process: HANDLE) {
        if !process.is_null() {
            unsafe { TerminateProcess(process, 1) };
        }
    }

    fn terminate_and_wait(process: HANDLE) -> Option<String> {
        terminate_unassigned_process(process);
        let wait = unsafe { WaitForSingleObject(process, u32::MAX) };
        (wait != WAIT_OBJECT_0).then(|| format!("cleanup wait returned {wait}"))
    }

    fn terminate_owned_job_and_wait(
        job: &WindowsOwnedResources,
        process: HANDLE,
    ) -> Option<String> {
        let termination = job.terminate(1).err();
        let wait = unsafe { WaitForSingleObject(process, u32::MAX) };
        let wait_failure = (wait != WAIT_OBJECT_0).then(|| format!("cleanup wait returned {wait}"));

        termination.or(wait_failure)
    }

    fn attach_cleanup(error: ProcessLaunchError, cleanup: Option<String>) -> ProcessLaunchError {
        match cleanup {
            Some(failure) => error.with_cleanup(failure),
            None => error,
        }
    }

    fn is_member(process: HANDLE, job: HANDLE) -> bool {
        let mut assigned = 0;
        unsafe { IsProcessInJob(process, job, &mut assigned) != 0 && assigned != 0 }
    }

    fn read_exit_code(process: HANDLE) -> Result<ChildExit, ProcessLaunchError> {
        let mut code = 0;
        if unsafe { GetExitCodeProcess(process, &mut code) } == 0 {
            return Err(ProcessLaunchError::operation(
                "read_exit_code",
                format!("GetExitCodeProcess failed: {}", unsafe { GetLastError() }),
            ));
        }

        Ok(ChildExit { code, signal: None })
    }

    pub(super) fn launch(spec: ChildLaunchSpec) -> Result<WindowsChildProcess, ProcessLaunchError> {
        launch_with_capture_limit(spec, 8 * 1024 * 1024, None)
    }

    pub(super) fn launch_with_capture_limit(
        spec: ChildLaunchSpec,
        max_capture_bytes: usize,
        environment: Option<&[(std::ffi::OsString, std::ffi::OsString)]>,
    ) -> Result<WindowsChildProcess, ProcessLaunchError> {
        WindowsChildProcess::launch_with_capture_limit(spec, max_capture_bytes, environment)
    }

    fn environment_block(
        environment: &[(std::ffi::OsString, std::ffi::OsString)],
    ) -> Result<Vec<u16>, ProcessLaunchError> {
        use std::os::windows::ffi::OsStrExt;

        let mut entries = environment.to_vec();
        entries.sort_by_cached_key(|(key, _)| key.to_string_lossy().to_ascii_lowercase());
        let mut block = Vec::new();
        for (key, value) in entries {
            if key.to_string_lossy().contains('\0')
                || value.to_string_lossy().contains('\0')
                || key.to_string_lossy().contains('=')
            {
                return Err(ProcessLaunchError::operation(
                    "create_process_environment",
                    "environment keys and values cannot contain NUL; keys cannot contain '='",
                ));
            }
            block.extend(key.encode_wide());
            block.push(u16::from(b'='));
            block.extend(value.encode_wide());
            block.push(0);
        }
        block.push(0);
        Ok(block)
    }

    pub(super) fn wait(process: &mut WindowsChildProcess) -> Result<ChildExit, ProcessLaunchError> {
        process.wait()
    }

    pub(super) fn try_wait(
        process: &WindowsChildProcess,
    ) -> Result<Option<ChildExit>, ProcessLaunchError> {
        process.try_wait()
    }

    pub(super) fn wait_with_settlement(
        process: &mut WindowsChildProcess,
    ) -> Result<ChildCompletion, ProcessLaunchError> {
        process.wait_with_settlement()
    }

    pub(super) fn read_output(
        process: &WindowsChildProcess,
    ) -> Result<ChildOutput, ProcessLaunchError> {
        process.read_output()
    }

    pub(super) fn write_input(
        process: &WindowsChildProcess,
        bytes: &[u8],
    ) -> Result<usize, ProcessLaunchError> {
        process.write_input_with_timeout(bytes, INPUT_WRITE_TIMEOUT_MILLISECONDS)
    }

    pub(super) fn write_input_with_timeout(
        process: &WindowsChildProcess,
        bytes: &[u8],
        timeout_milliseconds: u32,
    ) -> Result<usize, ProcessLaunchError> {
        process.write_input_with_timeout(bytes, timeout_milliseconds)
    }

    pub(super) fn close_input(process: &mut WindowsChildProcess) {
        process.close_input();
    }

    pub(super) fn drain_output(
        process: &WindowsChildProcess,
    ) -> Result<ChildOutput, ProcessLaunchError> {
        process.drain_output_with(|| false)
    }

    pub(super) fn drain_output_with<F>(
        process: &WindowsChildProcess,
        cancelled: F,
    ) -> Result<ChildOutput, ProcessLaunchError>
    where
        F: Fn() -> bool,
    {
        process.drain_output_with(cancelled)
    }

    pub(super) fn cancel(
        process: &mut WindowsChildProcess,
        exit_code: u32,
    ) -> Result<(), ProcessLaunchError> {
        process.cancel(exit_code)
    }

    pub(super) fn retry_cleanup(
        process: &mut WindowsChildProcess,
        exit_code: u32,
    ) -> Result<(), ProcessLaunchError> {
        process.retry_cleanup(exit_code)
    }

    pub(super) fn last_cleanup_failure(
        process: &WindowsChildProcess,
    ) -> Option<&ProcessLaunchError> {
        process.last_cleanup_failure()
    }

    pub(super) fn settlement(
        process: &WindowsChildProcess,
    ) -> Result<JobSettlement, ProcessLaunchError> {
        process.settlement()
    }

    pub(super) fn active_processes(
        process: &WindowsChildProcess,
    ) -> Result<u32, ProcessLaunchError> {
        process.active_processes()
    }

    pub(super) fn id(process: &WindowsChildProcess) -> u32 {
        unsafe { GetProcessId(process.process.raw()) }
    }

    #[cfg(test)]
    mod tests {
        use super::{CleanupExecutor, ProcessLaunchError, attach_cleanup, attempt_cleanup};

        struct FakeCleanup {
            events: Vec<&'static str>,
            fail_settlement_once: bool,
        }

        impl CleanupExecutor for FakeCleanup {
            fn terminate_for_cleanup(&mut self, _exit_code: u32) -> Result<(), ProcessLaunchError> {
                self.events.push("terminate");
                Ok(())
            }

            fn wait_for_cleanup(&mut self) -> Result<(), ProcessLaunchError> {
                self.events.push("wait");
                Ok(())
            }

            fn settle_for_cleanup(&mut self) -> Result<(), ProcessLaunchError> {
                self.events.push("settle");
                if self.fail_settlement_once {
                    self.fail_settlement_once = false;
                    return Err(ProcessLaunchError::operation(
                        "settle_job",
                        "late cleanup handshake failed",
                    ));
                }
                Ok(())
            }
        }

        #[test]
        fn cleanup_failure_is_retained_with_the_original_lifecycle_failure() {
            let error = ProcessLaunchError::operation("resume_process", "resume failed");
            let error = attach_cleanup(error, Some("job termination failed".to_owned()));

            assert_eq!(error.operation, "resume_process");
            assert_eq!(error.message, "resume failed");
            assert_eq!(error.cleanup.as_deref(), Some("job termination failed"));
        }

        #[test]
        fn late_cleanup_failure_keeps_the_owner_for_a_successful_retry() {
            let mut cleanup = FakeCleanup {
                events: Vec::new(),
                fail_settlement_once: true,
            };

            let first = attempt_cleanup(&mut cleanup, 1).expect_err("settlement should fail");
            assert_eq!(first.operation, "settle_job");
            assert_eq!(cleanup.events, vec!["terminate", "wait", "settle"]);

            attempt_cleanup(&mut cleanup, 1).expect("retry should complete cleanup");
            assert_eq!(
                cleanup.events,
                vec!["terminate", "wait", "settle", "terminate", "wait", "settle"]
            );
        }

        #[test]
        fn cleanup_attempts_later_phases_after_an_earlier_failure() {
            struct CancelledCleanup;

            impl CleanupExecutor for CancelledCleanup {
                fn terminate_for_cleanup(
                    &mut self,
                    _exit_code: u32,
                ) -> Result<(), ProcessLaunchError> {
                    Err(ProcessLaunchError::operation(
                        "terminate_job",
                        "cancellation arrived during final cleanup",
                    ))
                }

                fn wait_for_cleanup(&mut self) -> Result<(), ProcessLaunchError> {
                    Ok(())
                }

                fn settle_for_cleanup(&mut self) -> Result<(), ProcessLaunchError> {
                    Ok(())
                }
            }

            let mut cleanup = CancelledCleanup;
            let error =
                attempt_cleanup(&mut cleanup, 1).expect_err("cancellation should remain visible");
            assert_eq!(error.operation, "terminate_job");
        }
    }
}

#[cfg(windows)]
pub struct OwnedChildProcess(windows::WindowsChildProcess);

#[cfg(windows)]
impl std::fmt::Debug for OwnedChildProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedChildProcess")
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
#[derive(Clone)]
pub struct OwnedInputWriter(windows::WindowsInputWriter);

#[cfg(windows)]
impl OwnedInputWriter {
    pub fn write_input_with_timeout(
        &self,
        bytes: &[u8],
        timeout_milliseconds: u32,
    ) -> Result<usize, ProcessLaunchError> {
        self.0.write_input_with_timeout(bytes, timeout_milliseconds)
    }

    pub fn write_input_with_timeout_and_cancel(
        &self,
        bytes: &[u8],
        timeout_milliseconds: u32,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<usize, ProcessLaunchError> {
        self.0
            .write_input_with_timeout_and_cancel(bytes, timeout_milliseconds, cancelled)
    }
}

impl OwnedChildProcess {
    #[cfg(windows)]
    pub fn launch(spec: ChildLaunchSpec) -> Result<Self, ProcessLaunchError> {
        windows::launch(spec).map(Self)
    }

    #[cfg(windows)]
    pub fn launch_with_environment(
        spec: ChildLaunchSpec,
        environment: &[(OsString, OsString)],
        max_capture_bytes: usize,
    ) -> Result<Self, ProcessLaunchError> {
        windows::launch_with_capture_limit(spec, max_capture_bytes, Some(environment)).map(Self)
    }

    /// Protocol streaming is implemented by polling the Windows pipe. Callers
    /// that require `ChildStdout` are unavailable on Windows and receive an
    /// explicit launch error instead of inheriting an incomplete transport.
    #[cfg(windows)]
    pub fn launch_protocol(
        _spec: ChildLaunchSpec,
        _environment: &[(OsString, OsString)],
    ) -> Result<(Self, std::process::ChildStdout), ProcessLaunchError> {
        Err(ProcessLaunchError::operation(
            "launch_protocol",
            "streaming ChildStdout is unavailable on Windows",
        ))
    }

    #[cfg(windows)]
    pub fn launch_with_capture_limit(
        spec: ChildLaunchSpec,
        max_capture_bytes: usize,
    ) -> Result<Self, ProcessLaunchError> {
        windows::launch_with_capture_limit(spec, max_capture_bytes, None).map(Self)
    }

    #[cfg(windows)]
    pub fn wait(&mut self) -> Result<ChildExit, ProcessLaunchError> {
        windows::wait(&mut self.0)
    }

    #[cfg(windows)]
    pub fn wait_with_settlement(&mut self) -> Result<ChildCompletion, ProcessLaunchError> {
        windows::wait_with_settlement(&mut self.0)
    }

    #[cfg(windows)]
    pub fn try_wait(&self) -> Result<Option<ChildExit>, ProcessLaunchError> {
        windows::try_wait(&self.0)
    }

    #[cfg(windows)]
    pub fn read_output(&self) -> Result<ChildOutput, ProcessLaunchError> {
        windows::read_output(&self.0)
    }

    #[cfg(windows)]
    pub fn write_input(&self, bytes: &[u8]) -> Result<usize, ProcessLaunchError> {
        windows::write_input(&self.0, bytes)
    }

    #[cfg(windows)]
    pub fn input_writer(&self) -> Option<OwnedInputWriter> {
        self.0.input_writer().map(OwnedInputWriter)
    }

    #[cfg(windows)]
    pub fn write_input_with_timeout(
        &self,
        bytes: &[u8],
        timeout_milliseconds: u32,
    ) -> Result<usize, ProcessLaunchError> {
        windows::write_input_with_timeout(&self.0, bytes, timeout_milliseconds)
    }

    #[cfg(windows)]
    pub fn close_input(&mut self) {
        windows::close_input(&mut self.0);
    }

    #[cfg(windows)]
    pub fn drain_output(&self) -> Result<ChildOutput, ProcessLaunchError> {
        windows::drain_output(&self.0)
    }

    #[cfg(windows)]
    pub fn drain_output_with<F>(&self, cancelled: F) -> Result<ChildOutput, ProcessLaunchError>
    where
        F: Fn() -> bool,
    {
        windows::drain_output_with(&self.0, cancelled)
    }

    #[cfg(windows)]
    pub fn cancel(&mut self, exit_code: u32) -> Result<(), ProcessLaunchError> {
        windows::cancel(&mut self.0, exit_code)
    }

    #[cfg(windows)]
    pub fn retry_cleanup(&mut self, exit_code: u32) -> Result<(), ProcessLaunchError> {
        windows::retry_cleanup(&mut self.0, exit_code)
    }

    #[cfg(windows)]
    pub fn last_cleanup_failure(&self) -> Option<&ProcessLaunchError> {
        windows::last_cleanup_failure(&self.0)
    }

    #[cfg(windows)]
    pub fn settlement(&self) -> Result<JobSettlement, ProcessLaunchError> {
        windows::settlement(&self.0)
    }

    #[cfg(windows)]
    pub fn active_processes(&self) -> Result<u32, ProcessLaunchError> {
        windows::active_processes(&self.0)
    }

    #[cfg(windows)]
    pub fn id(&self) -> u32 {
        windows::id(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    use std::path::Path;

    #[cfg(windows)]
    #[test]
    fn affinity_policy_rejects_unprovable_narrow_cross_group_binding() {
        let result = super::windows::affinity_action(0b0010, 0b1111, Some(1), Some(2));
        assert_eq!(
            result.expect_err("a narrow affinity must not cross an unknown group boundary"),
            "caller CPU affinity cannot bound an owned process in another processor group"
        );
    }

    #[cfg(windows)]
    #[test]
    fn affinity_policy_skips_unconstrained_binding_when_groups_are_unknown() {
        assert_eq!(
            super::windows::affinity_action(0b1111, 0b1111, None, None),
            Ok(false)
        );
    }

    #[cfg(windows)]
    #[test]
    fn priority_preservation_reports_invalid_target_handles() {
        let error = super::windows::preserve_caller_priority(std::ptr::null_mut())
            .expect_err("a null process handle must not claim priority preservation");
        assert!(error.starts_with("SetPriorityClass failed:"));
    }

    #[cfg(windows)]
    #[test]
    fn token_owner_normalization_reports_invalid_target_handles() {
        let error = super::windows::normalize_child_token_owner(std::ptr::null_mut())
            .expect_err("a null process handle must not claim token ownership normalization");
        assert!(error.starts_with("OpenProcessToken failed:"));
    }

    #[cfg(windows)]
    #[test]
    fn owned_process_creation_preserves_unicode_and_suppresses_console_windows() {
        let flags = super::windows::owned_process_creation_flags();
        assert_ne!(
            flags & windows_sys::Win32::System::Threading::CREATE_SUSPENDED,
            0
        );
        assert_ne!(
            flags & windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT,
            0
        );
        assert_ne!(
            flags & windows_sys::Win32::System::Threading::CREATE_NO_WINDOW,
            0
        );
    }

    #[cfg(windows)]
    #[test]
    fn owned_windows_launch_rejects_relative_executables_before_job_creation() {
        let error = super::windows::validate_executable_path(Path::new("child.exe"))
            .expect_err("relative executable paths must not enter the owned launcher");

        assert_eq!(error.operation, "validate_executable");
        assert!(error.cleanup.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn owned_windows_launch_accepts_absolute_executables() {
        assert!(super::windows::validate_executable_path(Path::new(r"C:\child.exe")).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn output_poll_is_bounded_and_chunked_like_the_native_launcher() {
        assert_eq!(super::windows::requested_read_size(128, 0), 128);
        assert_eq!(
            super::windows::requested_read_size(1024 * 1024, 0),
            64 * 1024
        );
        assert_eq!(
            super::windows::requested_read_size(u32::MAX, 1024 * 1024 - 1),
            1
        );
        assert_eq!(
            super::windows::requested_read_size(u32::MAX, 1024 * 1024),
            0
        );
    }

    /// The helper mode is selected through the child environment so these
    /// tests can launch the real test executable without adding a test-only
    /// executable to the package.
    #[cfg(windows)]
    #[test]
    fn windows_stalled_stdin_helper() {
        if std::env::var_os("REA_LAUNCHER_STALLED_STDIN_HELPER").is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_large_output_helper() {
        if std::env::var_os("REA_LAUNCHER_LARGE_OUTPUT_HELPER").is_none() {
            return;
        }

        use std::io::Write;

        let output = vec![b'x'; 1_250_000];
        std::io::stdout()
            .write_all(&output)
            .expect("large-output helper should write to its pipe");
        std::io::stdout()
            .flush()
            .expect("large-output helper should flush its pipe");
    }

    #[cfg(windows)]
    #[test]
    fn stalled_protocol_input_honors_timeouts_and_cancellation() {
        use std::ffi::OsString;
        use std::time::{Duration, Instant};

        let executable = std::env::current_exe().expect("current test executable");
        let mut environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        environment.push((
            OsString::from("REA_LAUNCHER_STALLED_STDIN_HELPER"),
            OsString::from("1"),
        ));

        let spec = ChildLaunchSpec {
            executable,
            arguments: ChildLaunchSpec::arguments(["windows_stalled_stdin_helper", "--nocapture"]),
            working_directory: None,
            protocol_stdin: true,
            limits: WindowsJobLimits {
                memory_bytes: None,
                cpu_seconds: None,
            },
        };
        let mut child = OwnedChildProcess::launch_with_environment(spec, &environment, 64 * 1024)
            .expect("stalled-input helper should launch");

        let started = Instant::now();
        let error = child
            .write_input_with_timeout(&vec![b'x'; 1_250_000], 250)
            .expect_err("a child that never reads stdin must hit the write deadline");

        assert_eq!(error.operation, "write_input");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "write cancellation exceeded its bounded deadline: {:?}",
            started.elapsed()
        );

        let input = child.input_writer().expect("owned protocol input writer");
        let started = Instant::now();
        let error = input
            .write_input_with_timeout_and_cancel(&vec![b'x'; 1_250_000], 5_000, &|| {
                started.elapsed() >= Duration::from_millis(100)
            })
            .expect_err("request cancellation must interrupt a pending write");

        assert!(error.message.contains("cancelled"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "request cancellation waited for the full write timeout"
        );
        child.cancel(1).expect("stalled helper should be cancelled");
    }

    #[cfg(windows)]
    #[test]
    fn output_poll_drains_more_than_one_megabyte_from_the_real_child() {
        use std::ffi::OsString;
        use std::time::{Duration, Instant};

        let executable = std::env::current_exe().expect("current test executable");
        let mut environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        environment.push((
            OsString::from("REA_LAUNCHER_LARGE_OUTPUT_HELPER"),
            OsString::from("1"),
        ));

        let spec = ChildLaunchSpec {
            executable,
            arguments: ChildLaunchSpec::arguments(["windows_large_output_helper", "--nocapture"]),
            working_directory: None,
            protocol_stdin: false,
            limits: WindowsJobLimits {
                memory_bytes: None,
                cpu_seconds: None,
            },
        };
        let mut child =
            OwnedChildProcess::launch_with_environment(spec, &environment, 2 * 1024 * 1024)
                .expect("large-output helper should launch");

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut total_stdout = 0usize;
        let mut stdout_closed = false;
        while !stdout_closed && Instant::now() < deadline {
            let output = child.read_output().expect("output poll should succeed");
            total_stdout += output.stdout.len();
            stdout_closed = output.stdout_closed;

            if !stdout_closed {
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        assert!(stdout_closed, "large-output child did not close stdout");
        assert!(
            total_stdout > 1_000_000,
            "output poll retained only {total_stdout} bytes"
        );
        child
            .wait()
            .expect("large-output helper should exit cleanly");
    }

    #[cfg(not(windows))]
    #[test]
    fn launch_reports_spawn_failure_without_claiming_execution() {
        let result = OwnedChildProcess::launch(ChildLaunchSpec {
            executable: PathBuf::from("child.exe"),
            arguments: Vec::new(),
            working_directory: None,
            protocol_stdin: false,
            limits: WindowsJobLimits {
                memory_bytes: None,
                cpu_seconds: None,
            },
        });

        let error = result.expect_err("non-Windows launch should be unavailable");
        assert_eq!(error.operation, "create_process");
        assert!(error.cleanup.is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_try_wait_keeps_the_leader_waitable_until_cleanup() {
        use std::time::{Duration, Instant};

        let mut child = OwnedChildProcess::launch(ChildLaunchSpec {
            executable: PathBuf::from("/bin/sh"),
            arguments: ChildLaunchSpec::arguments(["-c", "exit 7"]),
            working_directory: None,
            protocol_stdin: false,
            limits: WindowsJobLimits {
                memory_bytes: None,
                cpu_seconds: None,
            },
        })
        .expect("shell should launch");

        let deadline = Instant::now() + Duration::from_secs(2);
        let exit = loop {
            if let Some(exit) = child.try_wait().expect("exit observation should succeed") {
                break exit;
            }
            assert!(
                Instant::now() < deadline,
                "shell did not exit before deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(exit.code, 7);
        assert_eq!(
            child
                .settlement()
                .expect("settlement should observe exit")
                .active_processes,
            0
        );

        child
            .cancel(1)
            .expect("cleanup should reap the observed leader and settle its group");
    }

    #[test]
    fn output_limit_accounts_for_both_streams_without_overflow() {
        let output = ChildOutput {
            stdout: vec![0; 4],
            stderr: vec![0; 4],
            stdout_closed: true,
            stderr_closed: true,
            output_incomplete: false,
            cancellation_observed: false,
        };
        assert!(!output.exceeds_limit(8));
        assert!(output.exceeds_limit(7));
        assert!(!output.exceeds_stream_limit(4, 4));
        assert!(output.exceeds_stream_limit(3, 4));
        assert!(output.exceeds_stream_limit(4, 3));
    }

    #[test]
    fn settlement_preserves_peak_memory_as_an_observation() {
        let settlement = JobSettlement {
            active_processes: 0,
            peak_memory_bytes: 4096,
            memory_limit_reached: false,
        };
        assert_eq!(settlement.active_processes, 0);
        assert_eq!(settlement.peak_memory_bytes, 4096);
        assert!(!settlement.memory_limit_reached);
    }

    #[test]
    fn completion_couples_exit_with_settlement_facts() {
        let completion = ChildCompletion {
            exit: ChildExit {
                code: 0,
                signal: None,
            },
            settlement: JobSettlement {
                active_processes: 0,
                peak_memory_bytes: 4096,
                memory_limit_reached: true,
            },
        };
        assert_eq!(completion.exit.code, 0);
        assert_eq!(completion.settlement.active_processes, 0);
        assert!(completion.settlement.memory_limit_reached);
    }

    #[test]
    fn output_retains_mixed_closure_and_cancellation_state_for_retry() {
        let incomplete = ChildOutput {
            stdout: vec![1, 2],
            stderr: vec![3],
            stdout_closed: true,
            stderr_closed: false,
            output_incomplete: true,
            cancellation_observed: false,
        };
        assert!(!incomplete.stdout_closed || !incomplete.stderr_closed);
        assert!(incomplete.output_incomplete);
        assert!(!incomplete.cancellation_observed);

        let cancelled = ChildOutput {
            cancellation_observed: true,
            ..incomplete
        };
        assert!(cancelled.cancellation_observed);
        assert!(cancelled.output_incomplete);
        assert_eq!(cancelled.stdout, vec![1, 2]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_output_result_preserves_incomplete_pipe_state() {
        let output = ChildOutput {
            stdout_closed: true,
            stderr_closed: false,
            output_incomplete: true,
            ..ChildOutput::default()
        };

        assert!(output.output_incomplete);
        assert!(!output.stderr_closed);
    }
}
