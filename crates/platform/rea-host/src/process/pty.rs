//! Owned pseudo-terminal child process (Unix).
//!
//! `portable-pty` owns only the PTY pair (open, resize, master I/O). The child
//! is spawned here with `std::process::Command` because portable-pty's
//! `spawn_command` silently substitutes `$HOME` for a missing working
//! directory, injects `SHELL`, and performs its own PATH search; each would
//! change caller-selected inputs.
//!
//! Ownership: the child becomes a session and process-group leader on the
//! PTY (setsid + TIOCSCTTY), its identity is verified with the shared
//! launcher primitives before any signal, and the leader stays unreaped until
//! the group is killed so its PID cannot be reused under us. Cleanup failures
//! are retained and retryable; `Drop` performs best-effort cleanup only.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use portable_pty::{MasterPty, PtySize, native_pty_system};

use super::launcher::unix::{verify_group_owner, verify_owned_process_group, wait_for_group_exit};
use super::launcher::{ChildExit, ProcessLaunchError};
use super::terminal::TerminalSize;

/// One master read, matching the 64 KiB buffer libuv/Node stream reads use.
const READ_CHUNK_SIZE: usize = 64 * 1024;
/// libuv `uv__read` reads at most this many full buffers per readiness.
const READS_PER_READINESS: usize = 32;
const WAIT_POLL: Duration = Duration::from_millis(5);
const ABANDON_REAP_DEADLINE: Duration = Duration::from_millis(250);

type RetainedChild = Arc<Mutex<Option<Child>>>;

static RETAINED_CHILDREN: OnceLock<Mutex<Vec<RetainedChild>>> = OnceLock::new();

/// One PTY launch. Every input is used exactly as given.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PtyLaunchSpec {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub working_directory: PathBuf,
    /// Complete child environment; nothing is inherited.
    pub environment: Vec<(OsString, OsString)>,
    pub size: TerminalSize,
}

/// One streamed observation from the PTY master, in arrival order.
#[derive(Debug, Eq, PartialEq)]
pub enum PtyEvent {
    /// Raw bytes exactly as read; `at` is when the read returned.
    Output { bytes: Vec<u8>, at: Instant },
    /// The master reached end of input (EOF or EIO once every slave closed).
    Closed { at: Instant },
    /// The master read failed for another reason.
    ReadFailed { message: String, at: Instant },
}

/// How a bounded wait ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtyWait {
    Exited(ChildExit),
    TimedOut,
    Cancelled,
}

/// Consumer-driven PTY output with node-pty/libuv read semantics.
///
/// Reads happen only when the consumer asks, on its own thread, as in
/// Node's event loop: `next_timeout` waits for readiness and then performs
/// one libuv read cycle (64 KiB reads until a short read, at most 32), one
/// event per read; `try_next` only returns events already read. A reader
/// thread blocked in read(2) instead wakes on the first bytes (for example
/// a line-discipline echo) and splits output that Node delivers whole.
/// Unread output stays in the kernel, so a busy consumer applies the same
/// backpressure to the child as a busy Node loop.
#[derive(Debug)]
pub struct PtyOutput {
    master: std::fs::File,
    queue: VecDeque<PtyEvent>,
    ended: bool,
}
impl PtyOutput {
    /// Wait up to `timeout` for the next event; `None` on timeout or after
    /// the stream ended and every event was delivered.
    pub fn next_timeout(&mut self, timeout: Duration) -> Option<PtyEvent> {
        if self.queue.is_empty() && !self.ended {
            match wait_readable(self.master.as_raw_fd(), timeout) {
                Ok(true) => self.read_cycle(),
                Ok(false) => {}
                Err(error) => self.end(PtyEvent::ReadFailed {
                    message: error.to_string(),
                    at: Instant::now(),
                }),
            }
        }
        self.queue.pop_front()
    }
    /// An event already read by a previous cycle, without reading again.
    pub fn try_next(&mut self) -> Option<PtyEvent> {
        self.queue.pop_front()
    }
    fn end(&mut self, event: PtyEvent) {
        self.ended = true;
        self.queue.push_back(event);
    }
    /// `uv__read`: full buffers continue the cycle; a short read ends it.
    fn read_cycle(&mut self) {
        let mut buffer = vec![0; READ_CHUNK_SIZE];
        for _ in 0..READS_PER_READINESS {
            match self.master.read(&mut buffer) {
                Ok(0) => return self.end(PtyEvent::Closed { at: Instant::now() }),
                Ok(count) => {
                    self.queue.push_back(PtyEvent::Output {
                        bytes: buffer[..count].to_vec(),
                        at: Instant::now(),
                    });
                    if count < READ_CHUNK_SIZE {
                        return;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                // Linux reports EIO on the master once every slave closed.
                Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                    return self.end(PtyEvent::Closed { at: Instant::now() });
                }
                Err(error) => {
                    return self.end(PtyEvent::ReadFailed {
                        message: error.to_string(),
                        at: Instant::now(),
                    });
                }
            }
        }
    }
}
pub struct OwnedPtyProcess {
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Mutex<Option<Box<dyn Write + Send>>>,
    child: Child,
    process_group_id: libc::pid_t,
    process_identity: String,
    exit: Option<ChildExit>,
    /// Whether the leader was reaped. It stays a zombie after its exit is
    /// observed so its PID, and so the group ID, remain ours until cleanup.
    reaped: bool,
    settled: bool,
    cleanup_failure: Option<ProcessLaunchError>,
}

impl std::fmt::Debug for OwnedPtyProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedPtyProcess")
            .field("process_group_id", &self.process_group_id)
            .field("exit", &self.exit)
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

fn failure(operation: &'static str, message: impl Into<String>) -> ProcessLaunchError {
    ProcessLaunchError {
        operation,
        message: message.into(),
        cleanup: None,
    }
}

fn pty_size(size: TerminalSize) -> PtySize {
    PtySize {
        rows: size.rows.get(),
        cols: size.columns.get(),
        pixel_width: 0,
        pixel_height: 0,
    }
}

impl OwnedPtyProcess {
    /// Open a PTY, start the child as its session leader and verify ownership.
    pub fn launch(spec: PtyLaunchSpec) -> Result<(Self, PtyOutput), ProcessLaunchError> {
        let pair = native_pty_system()
            .openpty(pty_size(spec.size))
            .map_err(|error| failure("open_pty", error.to_string()))?;
        let slave_path = pair
            .master
            .tty_name()
            .ok_or_else(|| failure("open_pty", "PTY slave path is unavailable"))?;
        // The original slave stays open in `pair.slave` until spawn returns,
        // so the path names the same device.
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(&slave_path)
            .map_err(|error| failure("open_pty_slave", error.to_string()))?;
        let stdio = |file: &std::fs::File| -> Result<Stdio, ProcessLaunchError> {
            file.try_clone()
                .map(Stdio::from)
                .map_err(|error| failure("open_pty_slave", error.to_string()))
        };

        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.arguments)
            .current_dir(&spec.working_directory)
            .env_clear()
            .envs(spec.environment.iter().map(|(key, value)| (key, value)))
            .stdin(stdio(&slave)?)
            .stdout(stdio(&slave)?)
            .stderr(stdio(&slave)?);
        // SAFETY: the closure only calls async-signal-safe libc functions
        // between fork and exec and touches no Rust allocations or locks.
        unsafe {
            command.pre_exec(|| {
                for signal in [
                    libc::SIGCHLD,
                    libc::SIGHUP,
                    libc::SIGINT,
                    libc::SIGQUIT,
                    libc::SIGTERM,
                    libc::SIGALRM,
                    libc::SIGPIPE,
                ] {
                    libc::signal(signal, libc::SIG_DFL);
                }
                let mut empty: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut empty);
                libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                #[allow(clippy::cast_lossless)]
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let spawned = command.spawn();
        drop(command);
        drop(slave);
        drop(pair.slave);
        let child = spawned.map_err(|error| failure("create_process", error.to_string()))?;

        let process_group_id = match libc::pid_t::try_from(child.id()) {
            Ok(pid) => pid,
            Err(_) => {
                return Err(abandon(
                    child,
                    failure("observe_process_group", "child PID is out of range"),
                ));
            }
        };
        // The leader is unreaped, so its PID (and group ID) cannot be reused.
        let process_identity = match verify_owned_process_group(process_group_id) {
            Ok(identity) => identity,
            Err(error) => {
                // The group identity is unknown here. The direct child handle
                // remains ours, but a negative-pid signal could target a
                // reused or foreign group. `abandon` only signals that child.
                return Err(abandon(child, error));
            }
        };

        let master = pair.master;
        let reader = dup_master(master.as_raw_fd()).map_err(|error| error.to_string());
        let writer = master.take_writer().map_err(|error| error.to_string());
        let (reader, writer) = match (reader, writer) {
            (Ok(reader), Ok(writer)) => (reader, writer),
            (Err(error), _) | (_, Err(error)) => {
                let mut launch_error = failure("open_pty_master", error.to_string());
                // SAFETY: the verified process group belongs to our unreaped child.
                if unsafe { libc::kill(-process_group_id, libc::SIGKILL) } != 0 {
                    launch_error.cleanup = Some(std::io::Error::last_os_error().to_string());
                }
                return Err(abandon(child, launch_error));
            }
        };

        Ok((
            Self {
                master: Mutex::new(master),
                writer: Mutex::new(Some(writer)),
                child,
                process_group_id,
                process_identity,
                exit: None,
                reaped: false,
                settled: false,
                cleanup_failure: None,
            },
            PtyOutput {
                master: reader,
                queue: VecDeque::new(),
                ended: false,
            },
        ))
    }

    /// The session, process-group and leader PID.
    pub fn id(&self) -> u32 {
        self.process_group_id as u32
    }

    /// Write terminal input exactly as given.
    pub fn write_input(&self, bytes: &[u8]) -> Result<(), ProcessLaunchError> {
        let mut writer = self.writer.lock().map_err(|_| poisoned("write_input"))?;
        let writer = writer
            .as_mut()
            .ok_or_else(|| failure("write_input", "PTY input is closed"))?;
        writer
            .write_all(bytes)
            .and_then(|()| writer.flush())
            .map_err(|error| failure("write_input", error.to_string()))
    }

    /// Resize the PTY; the kernel delivers SIGWINCH to the foreground group.
    pub fn resize(&self, size: TerminalSize) -> Result<(), ProcessLaunchError> {
        self.master
            .lock()
            .map_err(|_| poisoned("resize"))?
            .resize(pty_size(size))
            .map_err(|error| failure("resize", error.to_string()))
    }

    /// Signal only the leader after re-verifying its identity (node-pty
    /// `kill(signal)` semantics). An exited leader is not an error.
    pub fn signal_root(&mut self, signal: i32) -> Result<(), ProcessLaunchError> {
        self.signal_target(self.process_group_id, signal)
    }

    /// Signal the whole owned process group after re-verifying identity.
    pub fn signal_group(&mut self, signal: i32) -> Result<(), ProcessLaunchError> {
        self.signal_target(-self.process_group_id, signal)
    }

    fn signal_target(
        &mut self,
        target: libc::pid_t,
        signal: i32,
    ) -> Result<(), ProcessLaunchError> {
        if self.settled {
            return Ok(());
        }
        self.verify_unless_exited()?;
        if self.exit.is_some() && target > 0 {
            return Ok(());
        }
        // SAFETY: kill(2) with a verified owned PID/group and caller signal.
        if unsafe { libc::kill(target, signal) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        Err(failure("signal_process", error.to_string()))
    }

    /// Non-blocking leader exit observation (reaps once, then remembers).
    pub fn try_wait(&mut self) -> Result<Option<ChildExit>, ProcessLaunchError> {
        self.observe_exit()
    }

    /// Wait for the leader until `timeout` elapses or `cancelled` returns true.
    pub fn wait_bounded<F>(
        &mut self,
        timeout: Duration,
        cancelled: F,
    ) -> Result<PtyWait, ProcessLaunchError>
    where
        F: Fn() -> bool,
    {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(exit) = self.observe_exit()? {
                return Ok(PtyWait::Exited(exit));
            }
            if cancelled() {
                return Ok(PtyWait::Cancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(PtyWait::TimedOut);
            }
            std::thread::sleep(WAIT_POLL.min(deadline - now));
        }
    }

    /// SIGTERM the leader, wait up to `grace` (cancellation shortens it),
    /// then kill and settle the whole group. Returns the observed leader exit.
    pub fn terminate<F>(
        &mut self,
        grace: Duration,
        cancelled: F,
    ) -> Result<Option<ChildExit>, ProcessLaunchError>
    where
        F: Fn() -> bool,
    {
        if !grace.is_zero() && self.observe_exit()?.is_none() {
            self.signal_root(libc::SIGTERM)?;
            let _ = self.wait_bounded(grace, cancelled)?;
        }
        self.cancel()?;
        Ok(self.exit)
    }

    /// SIGKILL the owned group, reap the leader and verify the group is gone.
    /// A failure is retained and may be retried with `retry_cleanup`.
    pub fn cancel(&mut self) -> Result<(), ProcessLaunchError> {
        let result = self.cleanup();
        self.cleanup_failure = result.as_ref().err().cloned();
        result
    }

    pub fn retry_cleanup(&mut self) -> Result<(), ProcessLaunchError> {
        self.cancel()
    }

    pub fn last_cleanup_failure(&self) -> Option<&ProcessLaunchError> {
        self.cleanup_failure.as_ref()
    }

    pub fn is_settled(&self) -> bool {
        self.settled
    }

    fn cleanup(&mut self) -> Result<(), ProcessLaunchError> {
        if self.settled {
            return Ok(());
        }
        // Kill the group while the leader is still unreaped when possible so
        // the group ID is provably ours.
        self.verify_unless_exited()?;
        // SAFETY: kill(2) on the verified owned group (or a group whose
        // leader we reaped and whose ID is still unused if ESRCH follows).
        if unsafe { libc::kill(-self.process_group_id, libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            // macOS returns EPERM when every remaining member is a zombie;
            // settlement below polls until the group is provably gone.
            if !matches!(error.raw_os_error(), Some(libc::ESRCH | libc::EPERM)) {
                return Err(failure("terminate_process_group", error.to_string()));
            }
        }
        if !self.reaped {
            let status = self
                .child
                .wait()
                .map_err(|error| failure("wait", error.to_string()))?;
            self.reaped = true;
            self.exit.get_or_insert(child_exit(status));
        }
        wait_for_group_exit(self.process_group_id)?;
        if let Ok(mut writer) = self.writer.lock() {
            writer.take();
        }
        self.settled = true;
        Ok(())
    }

    /// Prove the leader is still our live child, or observe that it exited.
    /// An exiting leader can become unreadable to the identity observer
    /// before `try_wait` sees it; re-check exit before reporting a failure.
    fn verify_unless_exited(&mut self) -> Result<(), ProcessLaunchError> {
        if self.observe_exit()?.is_some() {
            return Ok(());
        }
        match verify_group_owner(self.process_group_id, &self.process_identity) {
            Ok(()) => Ok(()),
            Err(error) => {
                for _ in 0..20 {
                    if self.observe_exit()?.is_some() {
                        return Ok(());
                    }
                    std::thread::sleep(WAIT_POLL);
                }
                Err(error)
            }
        }
    }

    /// Observe the leader's exit while preserving the ownership state needed
    /// by cleanup. The zombie keeps its PID, and so the group ID, from being
    /// reused until cleanup reaps it.
    fn observe_exit(&mut self) -> Result<Option<ChildExit>, ProcessLaunchError> {
        if self.exit.is_none() {
            self.exit = peek_exit(self.process_group_id)
                .map_err(|error| failure("try_wait", error.to_string()))?;
        }
        Ok(self.exit)
    }
}

impl Drop for OwnedPtyProcess {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self.cleanup();
        }
    }
}

/// Non-reaping exit observation of our own unreaped child.
fn peek_exit(pid: libc::pid_t) -> std::io::Result<Option<ChildExit>> {
    loop {
        // SAFETY: a zeroed siginfo_t is a valid waitid out-parameter.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waitid on our own child; WNOWAIT leaves it waitable.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        #[cfg(target_os = "linux")]
        // SAFETY: waitid filled a SIGCHLD siginfo_t.
        let (child, status) = unsafe { (info.si_pid(), info.si_status()) };
        #[cfg(not(target_os = "linux"))]
        let (child, status) = (info.si_pid, info.si_status);
        if child == 0 {
            return Ok(None);
        }
        return Ok(Some(if info.si_code == libc::CLD_EXITED {
            ChildExit {
                code: status as u32,
                signal: None,
            }
        } else {
            ChildExit {
                code: 0,
                signal: Some(status),
            }
        }));
    }
}
fn child_exit(status: std::process::ExitStatus) -> ChildExit {
    ChildExit {
        code: status.code().unwrap_or_default() as u32,
        signal: status.signal(),
    }
}

fn poisoned(operation: &'static str) -> ProcessLaunchError {
    failure(operation, "PTY state lock was poisoned")
}

/// Give up a launch while retaining ownership until the child is reaped.
///
/// Launch failures can occur before a process-group identity is readable, so
/// this operation may only use the direct `Child` handle. A blocking
/// `Child::wait` here made a failed PTY launch hang the capture worker when a
/// platform process did not acknowledge the first cleanup attempt. Poll for a
/// short deadline and hand the still-owned child to a background reaper.
fn abandon(mut child: Child, mut error: ProcessLaunchError) -> ProcessLaunchError {
    let mut cleanup_errors = Vec::new();

    retry_retained_reapers(&mut cleanup_errors);

    if let Err(cleanup) = child.kill() {
        if cleanup.kind() != std::io::ErrorKind::InvalidInput {
            cleanup_errors.push(format!("kill child: {cleanup}"));
        }
    }

    let deadline = Instant::now() + ABANDON_REAP_DEADLINE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(WAIT_POLL),
            Ok(None) => {
                let pid = child.id();
                cleanup_errors.push(format!(
                    "child {pid} remained active after the bounded launch-cleanup deadline"
                ));
                schedule_reaping(child, &mut cleanup_errors);
                break;
            }
            Err(cleanup) => {
                cleanup_errors.push(format!("observe child: {cleanup}"));
                schedule_reaping(child, &mut cleanup_errors);
                break;
            }
        }
    }

    if !cleanup_errors.is_empty() {
        let details = cleanup_errors.join("; ");
        error.cleanup = Some(match error.cleanup.take() {
            Some(existing) => format!("{existing}; {details}"),
            None => details,
        });
    }
    error
}

fn schedule_reaping(child: Child, cleanup_errors: &mut Vec<String>) {
    let retained = Arc::new(Mutex::new(Some(child)));
    if let Err(cleanup) = spawn_reaper(Arc::clone(&retained)) {
        cleanup_errors.push(format!("retain child reaper: {cleanup}"));
        retain_for_retry(retained);
    }
}

fn reap_until_exit(mut child: Child) {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(WAIT_POLL),
            Err(_) => {
                // Keep ownership and retry observation rather than dropping
                // an active child after a transient wait error.
                std::thread::sleep(WAIT_POLL);
            }
        }
    }
}

fn spawn_reaper(owner: RetainedChild) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("rea-pty-abandon-reaper".to_owned())
        .spawn(move || {
            if let Some(child) = take_retained_child(&owner) {
                reap_until_exit(child);
            }
        })
}

fn retained_children() -> &'static Mutex<Vec<RetainedChild>> {
    RETAINED_CHILDREN.get_or_init(|| Mutex::new(Vec::new()))
}

fn retain_for_retry(owner: RetainedChild) {
    let mut retained = match retained_children().lock() {
        Ok(retained) => retained,
        Err(poisoned) => poisoned.into_inner(),
    };
    retained.push(owner);
}

fn retry_retained_reapers(cleanup_errors: &mut Vec<String>) {
    let pending = {
        let mut retained = match retained_children().lock() {
            Ok(retained) => retained,
            Err(poisoned) => poisoned.into_inner(),
        };
        std::mem::take(&mut *retained)
    };

    let mut retry = Vec::new();
    for owner in pending {
        if let Err(error) = spawn_reaper(Arc::clone(&owner)) {
            cleanup_errors.push(format!("retry retained child reaper: {error}"));
            retry.push(owner);
        }
    }

    if !retry.is_empty() {
        let mut retained = match retained_children().lock() {
            Ok(retained) => retained,
            Err(poisoned) => poisoned.into_inner(),
        };
        retained.extend(retry);
    }
}

fn take_retained_child(owner: &RetainedChild) -> Option<Child> {
    match owner.lock() {
        Ok(mut child) => child.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    }
}

/// A private duplicate of the master for `PtyOutput`, so readiness
/// polling never touches a descriptor number the owner may close and reuse.
fn dup_master(fd: Option<std::os::fd::RawFd>) -> std::io::Result<std::fs::File> {
    use std::os::fd::FromRawFd;
    let fd = fd.ok_or_else(|| std::io::Error::other("PTY master has no descriptor"))?;
    // SAFETY: fd is the live master owned by `pair.master`; F_DUPFD_CLOEXEC returns a new descriptor.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: duplicate is a fresh descriptor this function exclusively owns.
    Ok(unsafe { std::fs::File::from_raw_fd(duplicate) })
}
/// Wait up to `timeout` for the master to be readable, hung up or failed.
fn wait_readable(fd: std::os::fd::RawFd, timeout: Duration) -> std::io::Result<bool> {
    let deadline = Instant::now() + timeout;
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: one valid pollfd for a descriptor owned by the caller.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready > 0 {
            if poll.revents & libc::POLLNVAL != 0 {
                return Err(std::io::Error::from_raw_os_error(libc::EBADF));
            }
            if poll.revents & libc::POLLIN != 0 || poll.revents & libc::POLLERR != 0 {
                return Ok(true);
            }
            // A PTY master may report hangup while a descendant still holds
            // the slave open. Do not enter a blocking read for that status;
            // the caller will observe the owned leader's exit on its next
            // lifecycle poll and seal the already-queued output.
            if poll.revents & libc::POLLHUP != 0 {
                return Ok(false);
            }
            return Ok(false);
        }
        if ready == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::terminal::TerminalScreen;

    fn spec(script: &str) -> PtyLaunchSpec {
        PtyLaunchSpec {
            executable: PathBuf::from("/bin/sh"),
            arguments: vec!["-c".into(), script.into()],
            working_directory: std::env::temp_dir(),
            environment: vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("TERM".into(), "xterm-256color".into()),
            ],
            size: TerminalSize::new(40, 5).unwrap(),
        }
    }

    fn collect_until_closed(output: &mut PtyOutput) -> Vec<u8> {
        let mut bytes = Vec::new();
        while let Some(event) = output.next_timeout(Duration::from_secs(5)) {
            match event {
                PtyEvent::Output { bytes: chunk, .. } => bytes.extend(chunk),
                PtyEvent::Closed { .. } | PtyEvent::ReadFailed { .. } => break,
            }
        }
        bytes
    }

    #[test]
    fn streams_output_and_renders_screen() {
        let (mut process, mut output) =
            OwnedPtyProcess::launch(spec("printf 'hi\\033[1;31m!'; stty size")).unwrap();
        let bytes = collect_until_closed(&mut output);
        let exit = process
            .wait_bounded(Duration::from_secs(5), || false)
            .unwrap();
        assert_eq!(
            exit,
            PtyWait::Exited(ChildExit {
                code: 0,
                signal: None
            })
        );
        process.cancel().unwrap();
        let mut screen = TerminalScreen::new(TerminalSize::new(40, 5).unwrap(), 10);
        screen.write(&bytes);
        let lines = screen.snapshot().lines;
        assert_eq!(lines[0].trim_end(), "hi!5 40");
    }

    #[test]
    fn uses_only_the_explicit_environment_and_working_directory() {
        let (mut process, mut output) = OwnedPtyProcess::launch(spec(
            "printf '%s|%s|%s' \"$TERM\" \"${HOME-unset}\" \"$PWD\"",
        ))
        .unwrap();
        let text = String::from_utf8(collect_until_closed(&mut output)).unwrap();
        process.cancel().unwrap();
        assert!(text.starts_with("xterm-256color|unset|"), "{text}");
    }

    #[test]
    fn input_and_resize_reach_the_child() {
        let (mut process, mut output) =
            OwnedPtyProcess::launch(spec("read line; stty size; echo got:$line")).unwrap();
        process.resize(TerminalSize::new(70, 9).unwrap()).unwrap();
        process.write_input(b"abc\r").unwrap();
        let text = String::from_utf8_lossy(&collect_until_closed(&mut output)).into_owned();
        process.cancel().unwrap();
        assert!(text.contains("9 70") && text.contains("got:abc"), "{text}");
    }

    #[test]
    fn timeout_then_terminate_kills_group_including_grandchildren() {
        let (mut process, _output) =
            OwnedPtyProcess::launch(spec("trap '' TERM; sleep 30 & sleep 30")).unwrap();
        assert_eq!(
            process
                .wait_bounded(Duration::from_millis(50), || false)
                .unwrap(),
            PtyWait::TimedOut
        );
        let exit = process
            .terminate(Duration::from_millis(100), || false)
            .unwrap();
        assert_eq!(exit.and_then(|exit| exit.signal), Some(libc::SIGKILL));
        assert!(process.is_settled());
        // SAFETY: probe only; ESRCH proves the group is gone.
        assert_eq!(unsafe { libc::kill(-(process.id() as libc::pid_t), 0) }, -1);
    }

    #[test]
    fn cancellation_shortens_finalization_grace() {
        let (mut process, _output) =
            OwnedPtyProcess::launch(spec("trap '' TERM; sleep 30")).unwrap();
        let started = Instant::now();
        process.terminate(Duration::from_secs(20), || true).unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(process.is_settled());
    }

    #[test]
    fn root_signal_after_exit_is_not_an_error_and_cleanup_is_idempotent() {
        let (mut process, mut output) = OwnedPtyProcess::launch(spec("exit 3")).unwrap();
        collect_until_closed(&mut output);
        assert_eq!(
            process
                .wait_bounded(Duration::from_secs(5), || false)
                .unwrap(),
            PtyWait::Exited(ChildExit {
                code: 3,
                signal: None
            })
        );
        process.signal_root(libc::SIGTERM).unwrap();
        process.cancel().unwrap();
        process.retry_cleanup().unwrap();
        assert!(process.last_cleanup_failure().is_none());
    }

    #[test]
    #[ignore = "timing probe: prints cat echo/output chunking"]
    fn probe_cat_echo_chunking() {
        for _ in 0..10 {
            let mut launch = spec("");
            launch.executable = PathBuf::from("/bin/cat");
            launch.arguments.clear();
            let (mut process, mut output) = OwnedPtyProcess::launch(launch).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            process.write_input(b"hello\n").unwrap();
            let mut chunks = Vec::new();
            while let Some(PtyEvent::Output { bytes, .. }) =
                output.next_timeout(Duration::from_millis(100))
            {
                chunks.push(String::from_utf8_lossy(&bytes).into_owned());
            }
            eprintln!("{chunks:?}");
            process.cancel().unwrap();
        }
    }

    /// Reads follow libuv's 64 KiB buffer: bulk output arrives in frames no
    /// larger than one read and loses nothing across readiness cycles.
    #[test]
    fn bulk_output_frames_are_bounded_by_one_read_buffer() {
        let (mut process, mut output) =
            OwnedPtyProcess::launch(spec("head -c 300000 /dev/zero | tr '\\0' x")).unwrap();
        let mut total = 0;
        while let Some(event) = output.next_timeout(Duration::from_secs(5)) {
            match event {
                PtyEvent::Output { bytes, .. } => {
                    assert!(!bytes.is_empty() && bytes.len() <= READ_CHUNK_SIZE);
                    total += bytes.len();
                }
                PtyEvent::Closed { .. } | PtyEvent::ReadFailed { .. } => break,
            }
        }
        assert_eq!(total, 300_000);
        process.cancel().unwrap();
    }

    /// An observed exit must not reap the leader: its zombie keeps the PID
    /// and group ID ours until cleanup, so a later group signal or session
    /// attribution cannot reach a process that reused the ID.
    #[test]
    fn observed_exit_keeps_leader_unreaped_until_cleanup() {
        let (mut process, mut output) = OwnedPtyProcess::launch(spec("exit 0")).unwrap();
        collect_until_closed(&mut output);
        assert!(matches!(
            process
                .wait_bounded(Duration::from_secs(5), || false)
                .unwrap(),
            PtyWait::Exited(_)
        ));
        let pid = process.id() as libc::pid_t;
        // SAFETY: a zeroed siginfo_t is a valid waitid out-parameter.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: probe our own child without reaping it.
        let waitable = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        assert_eq!(waitable, 0, "leader was reaped before cleanup");
        process.cancel().unwrap();
        // SAFETY: as above; after cleanup the child is reaped (ECHILD).
        let reaped = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        assert_eq!(reaped, -1);
    }

    #[test]
    fn missing_working_directory_fails_instead_of_falling_back() {
        let mut launch = spec("true");
        launch.working_directory = PathBuf::from("/nonexistent/rea-pty");
        assert_eq!(
            OwnedPtyProcess::launch(launch).unwrap_err().operation,
            "create_process"
        );
    }
}
