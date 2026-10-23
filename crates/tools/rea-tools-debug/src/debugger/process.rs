//! Owned debugger process wrapper shared by gdb and rizin.
//!
//! Compatibility owners: `src/process/ProviderProcess.ts`
//! (`spawnOwnedProviderProcess`, `ProviderProcessSupervisor`) and the
//! owned-process stop paths of `src/process/ownedDebuggerSession.ts`.
//!
//! The process is launched through `rea_host::process::launcher` with
//! `launch_protocol`, so stdout is streamed to a bounded reader thread that
//! forwards raw bytes to the owning manager (which frames MI lines or NUL
//! frames). stderr stays captured (bounded) as process diagnostics. The
//! process runs in its own group, but debugger cleanup signals only the
//! directly owned leader (SIGTERM then SIGKILL) so inferiors are never killed
//! as a side effect.

use rea_host::process::launcher::{ChildExit, ChildLaunchSpec, OwnedChildProcess};
use rea_host::process::windows::job::WindowsJobLimits;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Maximum retained diagnostic (stderr) bytes (`MAX_DIAGNOSTIC_BYTES`).
pub(crate) const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;

/// Bounded stderr diagnostics plus observed/truncation/UTF-8 facts.
#[derive(Clone, Debug, Default)]
pub(crate) struct DiagnosticsSnapshot {
    pub(crate) stderr_text: String,
    pub(crate) stderr_bytes: usize,
    pub(crate) stderr_observed_bytes: u64,
    pub(crate) stderr_invalid_utf8: bool,
    pub(crate) diagnostic_truncated: bool,
    pub(crate) exit_code: Option<i64>,
    pub(crate) signal: Option<String>,
}

/// POSIX terminating-signal name, like `ProviderProcess.ts` signal reporting.
pub(crate) fn signal_name(signal: i32) -> String {
    let name = match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        _ => return format!("SIG{signal}"),
    };
    name.to_owned()
}

struct StderrCapture {
    bytes: Vec<u8>,
    observed: u64,
    truncated: bool,
}

impl StderrCapture {
    fn append(&mut self, chunk: &[u8]) {
        self.observed += chunk.len() as u64;
        let remaining = MAX_DIAGNOSTIC_BYTES.saturating_sub(self.bytes.len());
        if remaining == 0 {
            if !chunk.is_empty() {
                self.truncated = true;
            }
            return;
        }
        if chunk.len() > remaining {
            self.bytes.extend_from_slice(&chunk[..remaining]);
            self.truncated = true;
        } else {
            self.bytes.extend_from_slice(chunk);
        }
    }
}

/// Owned debugger process with a streamed stdout reader.
pub(crate) struct DebuggerProcess {
    child: Mutex<OwnedChildProcess>,
    leader_pid: u32,
    exit: Mutex<Option<ChildExit>>,
    stdout_closed: Arc<AtomicBool>,
    stderr_seen: Mutex<usize>,
    stderr: Mutex<StderrCapture>,
    exit_notify: (Mutex<bool>, Condvar),
    disposed: AtomicBool,
}

impl DebuggerProcess {
    /// Spawn `command` with `arguments` and a complete child environment made of
    /// the host snapshot plus `REA_PROCESS_RUN_ID` (`spawnOwnedProviderProcess`).
    pub(crate) fn spawn(
        command: &str,
        arguments: &[String],
        host_environment: &HashMap<String, String>,
        run_id: &str,
        on_stdout: impl Fn(&[u8]) + Send + 'static,
        on_stdout_eof: impl Fn() + Send + 'static,
    ) -> Result<Arc<Self>, String> {
        let spec = ChildLaunchSpec {
            executable: PathBuf::from(command),
            arguments: ChildLaunchSpec::arguments(arguments.iter().cloned()),
            working_directory: None,
            protocol_stdin: true,
            limits: WindowsJobLimits {
                memory_bytes: None,
                cpu_seconds: None,
            },
        };
        let mut environment: HashMap<String, String> = host_environment.clone();
        environment.insert("REA_PROCESS_RUN_ID".to_owned(), run_id.to_owned());
        let env: Vec<(OsString, OsString)> = environment
            .into_iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect();

        let (child, stdout) =
            OwnedChildProcess::launch_protocol(spec, &env).map_err(|error| error.to_string())?;
        let leader_pid = child.id();

        let stdout_closed = Arc::new(AtomicBool::new(false));

        let owned = Arc::new(Self {
            child: Mutex::new(child),
            leader_pid,
            exit: Mutex::new(None),
            stdout_closed: Arc::clone(&stdout_closed),
            stderr_seen: Mutex::new(0),
            stderr: Mutex::new(StderrCapture {
                bytes: Vec::new(),
                observed: 0,
                truncated: false,
            }),
            exit_notify: (Mutex::new(false), Condvar::new()),
            disposed: AtomicBool::new(false),
        });

        spawn_stdout_reader(stdout, stdout_closed, on_stdout, on_stdout_eof);

        Ok(owned)
    }

    /// Drain captured stderr from the child and record exit when observed.
    fn pump(&self) {
        let output = {
            let child = self
                .child
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            child.read_output().ok()
        };
        if let Some(output) = output {
            let mut seen = self
                .stderr_seen
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if output.stderr.len() > *seen {
                let new = output.stderr[*seen..].to_vec();
                *seen = output.stderr.len();
                drop(seen);
                self.stderr
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .append(&new);
            }
        }
        if let Ok(Some(exit)) = self.try_wait() {
            self.record_exit(exit);
        }
    }

    pub(crate) fn leader_pid(&self) -> u32 {
        self.leader_pid
    }

    pub(crate) fn try_wait(&self) -> Result<Option<ChildExit>, String> {
        let child = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        child.try_wait().map_err(|error| error.to_string())
    }

    fn record_exit(&self, exit: ChildExit) {
        let mut slot = self
            .exit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.is_none() {
            *slot = Some(exit);
        }
        let (lock, cvar) = &self.exit_notify;
        let mut exited = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *exited = true;
        cvar.notify_all();
    }

    pub(crate) fn exit(&self) -> Option<ChildExit> {
        *self
            .exit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Write bytes to the protocol stdin.
    pub(crate) fn write_stdin(&self, bytes: &[u8]) -> Result<(), String> {
        let child = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        child
            .write_input(bytes)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub(crate) fn stdin_writable(&self) -> bool {
        let child = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        child.try_wait().ok().flatten().is_none()
    }

    /// Diagnostics snapshot (`ProviderProcessSupervisor.snapshot`).
    pub(crate) fn diagnostics(&self) -> DiagnosticsSnapshot {
        self.pump();
        let capture = self
            .stderr
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let text = String::from_utf8_lossy(&capture.bytes).into_owned();
        let stderr_invalid_utf8 = std::str::from_utf8(&capture.bytes).is_err();
        let exit = self.exit();
        DiagnosticsSnapshot {
            stderr_text: text,
            stderr_bytes: capture.bytes.len(),
            stderr_observed_bytes: capture.observed,
            stderr_invalid_utf8,
            diagnostic_truncated: capture.truncated,
            exit_code: exit.map(|exit| i64::from(exit.code)),
            signal: exit.and_then(|exit| exit.signal.map(signal_name)),
        }
    }

    /// Cap additional retained stdout bytes (`limitAdditionalOutputBytes`).
    /// The framing owner enforces its own per-command bounds; nothing extra is
    /// retained here beyond draining to settlement.
    pub(crate) fn limit_additional_output_bytes(&self, _max_bytes: usize) {}

    /// Verify inherited output streams closed within the timeout
    /// (`waitForOutputClose`). Drains stderr diagnostics while waiting.
    pub(crate) fn wait_for_output_close(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            self.pump();
            let stderr_closed = {
                let child = self
                    .child
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                child
                    .read_output()
                    .map(|output| output.stderr_closed)
                    .unwrap_or(false)
            };
            if self.stdout_closed.load(Ordering::SeqCst) && stderr_closed {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            std::thread::sleep((deadline - now).min(Duration::from_millis(5)));
        }
    }

    /// Wait for the owned process to exit within the timeout.
    pub(crate) fn wait_for_exit(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(Some(exit)) = self.try_wait() {
                self.record_exit(exit);
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            std::thread::sleep((deadline - now).min(Duration::from_millis(5)));
        }
    }

    /// Signal only the directly owned leader (never the group) with SIGTERM.
    pub(crate) fn term_leader(&self) -> Result<(), String> {
        platform::signal_leader(self.leader_pid, platform::LeaderSignal::Term)
    }

    /// Signal only the directly owned leader with SIGKILL.
    pub(crate) fn kill_leader(&self) -> Result<(), String> {
        platform::signal_leader(self.leader_pid, platform::LeaderSignal::Kill)
    }

    pub(crate) fn unref_output_streams(&self) {
        // Reader threads are detached; nothing to unref explicitly.
    }

    /// Release the owned process group after confirmed settlement.
    pub(crate) fn dispose(&self) {
        if self.disposed.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut child = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Final settlement of the whole process group; the leader has already
        // exited by the time dispose runs in the normal stop path.
        let _ = child.cancel(143);
    }
}

fn spawn_stdout_reader(
    mut stdout: std::process::ChildStdout,
    stdout_closed: Arc<AtomicBool>,
    on_stdout: impl Fn(&[u8]) + Send + 'static,
    on_stdout_eof: impl Fn() + Send + 'static,
) {
    std::thread::spawn(move || {
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => on_stdout(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        stdout_closed.store(true, Ordering::SeqCst);
        on_stdout_eof();
    });
}

#[cfg(target_os = "linux")]
mod platform {
    use rustix::process::{Pid, Signal, kill_process};

    #[derive(Clone, Copy)]
    pub(super) enum LeaderSignal {
        Term,
        Kill,
    }

    pub(super) fn signal_leader(pid: u32, signal: LeaderSignal) -> Result<(), String> {
        let pid = i32::try_from(pid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or_else(|| "owned debugger leader PID is invalid".to_owned())?;
        let signal = match signal {
            LeaderSignal::Term => Signal::TERM,
            LeaderSignal::Kill => Signal::KILL,
        };
        match kill_process(pid, signal) {
            Ok(()) => Ok(()),
            // The leader already exited; signalling is a no-op success.
            Err(error) if error == rustix::io::Errno::SRCH => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    #[derive(Clone, Copy)]
    pub(super) enum LeaderSignal {
        Term,
        Kill,
    }

    pub(super) fn signal_leader(_pid: u32, _signal: LeaderSignal) -> Result<(), String> {
        // Non-Linux hosts never start a persistent debugger session, so the
        // stop path is unreachable here; fail closed if ever called.
        Err("Owned debugger process termination is only implemented on Linux.".to_owned())
    }
}
