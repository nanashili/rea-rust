//! Explicit, owned client for the optional Rust Ghidra worker.
//!
//! Provider selection is deliberately kept here.  Callers must opt in through
//! the documented environment variables before a worker can be started; the
//! host never silently falls back to this provider.  The worker remains owned
//! until its close acknowledgement and process-group settlement are observed.

use std::{
    env, fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use crate::{
    ghidra_rust::protocol::{
        self as protocol, WorkerFrame, WorkerFunctionPage, WorkerInfo, WorkerResolution,
        WorkerSegments,
    },
    process::launcher::{ChildLaunchSpec, OwnedChildProcess, ProcessLaunchError},
    process::windows::job::WindowsJobLimits,
};

mod progress;
use self::progress::{ProgressBuffer, ProgressUpdate, WorkerProgress};

const WORKER_ARGUMENT: &str = "--rea-rust-ghidra-worker";
const MAX_STDERR_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConfig {
    pub executable: PathBuf,
    pub cache_directory: PathBuf,
    pub timeout: Duration,
}

impl ProviderConfig {
    /// Read the explicit provider selection from the process environment.
    pub fn from_environment() -> Result<Self, ProviderError> {
        if env::var("REA_ANALYSIS_PROVIDER").as_deref() != Ok("ghidra-rust")
            || env::var("REA_GHIDRA_RUST_ENABLED").as_deref() != Ok("true")
        {
            return Err(ProviderError::Unavailable(
                "Rust Ghidra provider is not explicitly enabled".into(),
            ));
        }
        if !cfg!(target_os = "macos") && !cfg!(target_os = "linux") {
            return Err(ProviderError::Unavailable(
                "The Rust Ghidra provider requires macOS or Linux".into(),
            ));
        }

        let executable = absolute_environment_path("REA_GHIDRA_RUST_WORKER")?;
        let cache_directory = absolute_environment_path("REA_GHIDRA_RUST_CACHE_DIR")?;
        let timeout_text = env::var("REA_GHIDRA_RUST_TIMEOUT_MS").map_err(|_| {
            ProviderError::InvalidConfiguration("REA_GHIDRA_RUST_TIMEOUT_MS is required".into())
        })?;
        if timeout_text.is_empty() || !timeout_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ProviderError::InvalidConfiguration(
                "REA_GHIDRA_RUST_TIMEOUT_MS must contain only decimal digits".into(),
            ));
        }
        let timeout_ms = timeout_text.parse::<u64>().map_err(|_| {
            ProviderError::InvalidConfiguration("REA_GHIDRA_RUST_TIMEOUT_MS is too large".into())
        })?;
        if !(1..=2_147_483_647).contains(&timeout_ms) {
            return Err(ProviderError::InvalidConfiguration(
                "REA_GHIDRA_RUST_TIMEOUT_MS must be between 1 and 2147483647".into(),
            ));
        }
        validate_executable(&executable)?;

        Ok(Self {
            executable,
            cache_directory,
            timeout: Duration::from_millis(timeout_ms),
        })
    }
}

#[derive(Debug)]
pub enum ProviderError {
    Unavailable(String),
    InvalidConfiguration(String),
    Launch(String),
    Protocol(protocol::WorkerProtocolError),
    Transport(String),
    Cancelled,
    Timeout,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message)
            | Self::InvalidConfiguration(message)
            | Self::Launch(message)
            | Self::Transport(message) => formatter.write_str(message),
            Self::Protocol(error) => error.fmt(formatter),
            Self::Cancelled => formatter.write_str("Rust Ghidra provider operation was cancelled"),
            Self::Timeout => formatter.write_str("Rust Ghidra provider operation timed out"),
        }
    }
}

impl std::error::Error for ProviderError {}

impl From<protocol::WorkerProtocolError> for ProviderError {
    fn from(error: protocol::WorkerProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<ProcessLaunchError> for ProviderError {
    fn from(error: ProcessLaunchError) -> Self {
        Self::Launch(error.message)
    }
}

pub struct GhidraRustProvider {
    config: ProviderConfig,
    child: OwnedChildProcess,
    decoder: protocol::LineDecoder,
    stdout_read: usize,
    next_id: u64,
    target_sha256: Option<String>,
    inventory_sha256: Option<String>,
    cleanup_failure: Option<String>,
    closed: bool,
    progress_buffer: ProgressBuffer,
    progress_sequence: usize,
    progress_coalesced: bool,
}

impl GhidraRustProvider {
    pub fn start(config: ProviderConfig) -> Result<Self, ProviderError> {
        if !config.executable.is_absolute() {
            return Err(ProviderError::InvalidConfiguration(
                "REA_GHIDRA_RUST_WORKER must be an absolute path".into(),
            ));
        }
        if !config.cache_directory.is_absolute() {
            return Err(ProviderError::InvalidConfiguration(
                "REA_GHIDRA_RUST_CACHE_DIR must be an absolute path".into(),
            ));
        }
        let child = OwnedChildProcess::launch(ChildLaunchSpec {
            executable: config.executable.clone(),
            arguments: ChildLaunchSpec::arguments([WORKER_ARGUMENT]),
            working_directory: None,
            protocol_stdin: true,
            limits: WindowsJobLimits {
                memory_bytes: None,
                cpu_seconds: None,
            },
        })?;
        Ok(Self {
            config,
            child,
            decoder: protocol::LineDecoder::new(),
            stdout_read: 0,
            next_id: 1,
            target_sha256: None,
            inventory_sha256: None,
            cleanup_failure: None,
            closed: false,
            progress_buffer: ProgressBuffer::new(),
            progress_sequence: 0,
            progress_coalesced: false,
        })
    }

    pub fn info(&mut self) -> Result<WorkerInfo, ProviderError> {
        self.info_with_cancel(|| false)
    }

    pub fn info_with_cancel<F>(&mut self, cancelled: F) -> Result<WorkerInfo, ProviderError>
    where
        F: Fn() -> bool,
    {
        let id = self.allocate_id()?;
        let frame = self.request_with_cancel(protocol::WorkerRequest::info(id), &cancelled)?;
        Ok(protocol::decode_info(frame, id)?)
    }

    pub fn open(&mut self, path: &str, target_sha256: &str) -> Result<WorkerInfo, ProviderError> {
        self.open_with_cancel(path, target_sha256, || false)
    }

    pub fn open_with_cancel<F>(
        &mut self,
        path: &str,
        target_sha256: &str,
        cancelled: F,
    ) -> Result<WorkerInfo, ProviderError>
    where
        F: Fn() -> bool,
    {
        let id = self.allocate_id()?;
        let frame = self.request_with_cancel(
            protocol::WorkerRequest::open(id, path, target_sha256),
            &cancelled,
        )?;
        let info = protocol::decode_info(frame, id)?;
        info.require_target(target_sha256)?;
        self.target_sha256 = Some(target_sha256.to_owned());
        self.inventory_sha256 = info.inventory_sha256.clone();
        Ok(info)
    }

    pub fn functions(
        &mut self,
        offset: usize,
        limit: usize,
    ) -> Result<WorkerFunctionPage, ProviderError> {
        self.functions_with_cancel(offset, limit, || false)
    }

    pub fn functions_with_cancel<F>(
        &mut self,
        offset: usize,
        limit: usize,
        cancelled: F,
    ) -> Result<WorkerFunctionPage, ProviderError>
    where
        F: Fn() -> bool,
    {
        let id = self.allocate_id()?;
        let frame = self.request_with_cancel(
            protocol::WorkerRequest::functions(id, offset, limit),
            &cancelled,
        )?;
        let page = protocol::decode_function_page(frame, id)?;
        self.require_inventory(&page.inventory_sha256)?;
        Ok(page)
    }

    pub fn resolve_functions(
        &mut self,
        selectors: &[String],
    ) -> Result<WorkerResolution, ProviderError> {
        self.resolve_functions_with_cancel(selectors, || false)
    }

    pub fn resolve_functions_with_cancel<F>(
        &mut self,
        selectors: &[String],
        cancelled: F,
    ) -> Result<WorkerResolution, ProviderError>
    where
        F: Fn() -> bool,
    {
        let id = self.allocate_id()?;
        let frame = self.request_with_cancel(
            protocol::WorkerRequest::resolve_functions(id, selectors),
            &cancelled,
        )?;
        let result = protocol::decode_resolution(frame, id)?;
        self.require_inventory(&result.inventory_sha256)?;
        Ok(result)
    }

    pub fn segments(&mut self) -> Result<WorkerSegments, ProviderError> {
        self.segments_with_cancel(|| false)
    }

    pub fn segments_with_cancel<F>(&mut self, cancelled: F) -> Result<WorkerSegments, ProviderError>
    where
        F: Fn() -> bool,
    {
        let id = self.allocate_id()?;
        let frame = self.request_with_cancel(protocol::WorkerRequest::segments(id), &cancelled)?;
        Ok(protocol::decode_segments(frame, id)?)
    }

    /// Submit one bounded decompilation batch.  The application layer owns
    /// the result schema because it also owns Evidence projection; this host
    /// boundary returns the authenticated worker frame without reinterpreting
    /// pseudocode facts.
    pub fn batch_decompile(&mut self, addresses: &[String]) -> Result<WorkerFrame, ProviderError> {
        self.batch_decompile_with_cancel(addresses, || false)
    }

    pub fn batch_decompile_with_cancel<F>(
        &mut self,
        addresses: &[String],
        cancelled: F,
    ) -> Result<WorkerFrame, ProviderError>
    where
        F: Fn() -> bool,
    {
        self.batch_decompile_with_options(addresses, false, cancelled)
    }

    pub fn batch_decompile_cache_only_with_cancel<F>(
        &mut self,
        addresses: &[String],
        cancelled: F,
    ) -> Result<WorkerFrame, ProviderError>
    where
        F: Fn() -> bool,
    {
        self.batch_decompile_with_options(addresses, true, cancelled)
    }

    fn batch_decompile_with_options<F>(
        &mut self,
        addresses: &[String],
        cache_only: bool,
        cancelled: F,
    ) -> Result<WorkerFrame, ProviderError>
    where
        F: Fn() -> bool,
    {
        let id = self.allocate_id()?;
        self.request_with_cancel(
            protocol::WorkerRequest::batch_decompile_with_cache(id, addresses, cache_only),
            &cancelled,
        )
    }

    pub fn checkpoint(&mut self) -> Result<(), ProviderError> {
        self.checkpoint_with_cancel(|| false)
    }

    pub fn checkpoint_with_cancel<F>(&mut self, cancelled: F) -> Result<(), ProviderError>
    where
        F: Fn() -> bool,
    {
        let id = self.allocate_id()?;
        let frame =
            self.request_with_cancel(protocol::WorkerRequest::checkpoint(id), &cancelled)?;
        protocol::decode_checkpoint(frame, id)?;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), ProviderError> {
        self.close_with_cancel(|| false)
    }

    pub fn close_with_cancel<F>(&mut self, cancelled: F) -> Result<(), ProviderError>
    where
        F: Fn() -> bool,
    {
        if self.closed {
            return Ok(());
        }

        let id = self.allocate_id()?;
        let frame = self.request_with_cancel(protocol::WorkerRequest::close(id), &cancelled)?;
        protocol::decode_close(frame, id)?;
        self.child.close_input();
        if let Err(error) = self.wait_for_exit_with_cancel(&cancelled) {
            self.record_cleanup_failure();
            return Err(error);
        }
        self.closed = true;
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), ProviderError> {
        self.child.cancel(1).map_err(ProviderError::from)
    }

    pub fn cleanup_failure(&self) -> Option<&str> {
        self.cleanup_failure.as_deref()
    }

    pub fn take_progress(&mut self) -> Option<ProgressUpdate> {
        self.progress_buffer.take_latest()
    }

    pub fn progress_was_coalesced(&self) -> bool {
        self.progress_coalesced
    }

    pub fn clear_progress_coalesced(&mut self) {
        self.progress_coalesced = false;
    }

    /// Send one protocol request while polling the owned child.  The callback
    /// is evaluated between polls so application cancellation can terminate
    /// the same owned process group as timeout cleanup.
    pub fn request_with_cancel<F>(
        &mut self,
        request: Result<protocol::WorkerRequest, String>,
        cancelled: F,
    ) -> Result<WorkerFrame, ProviderError>
    where
        F: Fn() -> bool,
    {
        if self.closed {
            return Err(ProviderError::Transport(
                "Rust Ghidra provider is closed".into(),
            ));
        }

        if cancelled() {
            self.cancel()?;
            return Err(ProviderError::Cancelled);
        }

        let request = request.map_err(ProviderError::Transport)?;
        let encoded = request.encode_line().map_err(ProviderError::Transport)?;
        self.child
            .write_input(&encoded)
            .map_err(ProviderError::from)?;
        let deadline = Instant::now() + self.config.timeout;
        loop {
            if cancelled() {
                self.cancel()?;
                return Err(ProviderError::Cancelled);
            }
            if Instant::now() >= deadline {
                self.cancel()?;
                return Err(ProviderError::Timeout);
            }
            let mut response = None;
            for frame in self.read_frames()? {
                match frame {
                    WorkerFrame::Progress {
                        label,
                        completed,
                        total,
                    } if response.is_none() => {
                        if self.progress_buffer.take_latest().is_some() {
                            self.progress_coalesced = true;
                        }
                        self.progress_sequence =
                            self.progress_sequence.checked_add(1).ok_or_else(|| {
                                ProviderError::Transport(
                                    "worker progress sequence exhausted".into(),
                                )
                            })?;
                        self.progress_buffer
                            .accept(
                                self.progress_sequence,
                                request.method(),
                                WorkerProgress::new(label, completed, total)
                                    .map_err(ProviderError::Transport)?,
                            )
                            .map_err(ProviderError::Transport)?;
                    }
                    WorkerFrame::Reply { id, result }
                        if id == request.id() && response.is_none() =>
                    {
                        response = Some(WorkerFrame::Reply { id, result });
                    }
                    WorkerFrame::Error {
                        id,
                        code,
                        message,
                        error_code,
                    } if id == request.id() && response.is_none() => {
                        response = Some(WorkerFrame::Error {
                            id,
                            code,
                            message,
                            error_code,
                        });
                    }
                    WorkerFrame::Progress { .. } => {
                        return Err(ProviderError::Protocol(
                            protocol::WorkerProtocolError::Malformed(
                                "worker progress arrived after its reply".into(),
                            ),
                        ));
                    }
                    WorkerFrame::Reply { .. } | WorkerFrame::Error { .. } if response.is_some() => {
                        return Err(ProviderError::Protocol(
                            protocol::WorkerProtocolError::Malformed(
                                "worker emitted more than one reply".into(),
                            ),
                        ));
                    }
                    WorkerFrame::Reply { id, .. } | WorkerFrame::Error { id, .. } => {
                        return Err(ProviderError::Protocol(
                            protocol::WorkerProtocolError::UnexpectedReply {
                                expected: request.id(),
                                actual: id,
                            },
                        ));
                    }
                }
            }
            if let Some(response) = response {
                return Ok(response);
            }
            if let Some(exit) = self.child.try_wait().map_err(ProviderError::from)? {
                let output = self.child.drain_output().map_err(ProviderError::from)?;
                return Err(ProviderError::Transport(format!(
                    "worker exited before reply ({}): {}",
                    exit.code,
                    bounded_stderr(&output.stderr)
                )));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn read_frames(&mut self) -> Result<Vec<WorkerFrame>, ProviderError> {
        let output = self.child.read_output().map_err(ProviderError::from)?;
        if output.stderr.len() > MAX_STDERR_BYTES {
            return Err(ProviderError::Transport(
                "worker diagnostics exceed the bounded size".into(),
            ));
        }
        if self.stdout_read > output.stdout.len() {
            return Err(ProviderError::Transport("worker stdout regressed".into()));
        }
        let new_bytes = &output.stdout[self.stdout_read..];
        self.stdout_read = output.stdout.len();
        self.decoder
            .push(new_bytes)
            .map_err(ProviderError::Transport)
    }

    fn wait_for_exit_with_cancel<F>(&mut self, cancelled: F) -> Result<(), ProviderError>
    where
        F: Fn() -> bool,
    {
        let deadline = Instant::now() + self.config.timeout;
        loop {
            if cancelled() {
                self.cancel()?;
                return Err(ProviderError::Cancelled);
            }
            if let Some(_) = self.child.try_wait().map_err(ProviderError::from)? {
                let output = self
                    .child
                    .drain_output_with(&cancelled)
                    .map_err(ProviderError::from)?;
                if output.cancellation_observed {
                    self.cancel()?;
                    return Err(ProviderError::Cancelled);
                }
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.child.cancel(1).map_err(ProviderError::from)?;
                return Err(ProviderError::Timeout);
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn record_cleanup_failure(&mut self) {
        if let Some(error) = self.child.last_cleanup_failure() {
            self.cleanup_failure = Some(error.message.clone());
        }
    }

    fn require_inventory(&self, inventory: &str) -> Result<(), ProviderError> {
        match self.inventory_sha256.as_deref() {
            Some(expected) if expected == inventory => Ok(()),
            Some(_) => Err(ProviderError::Transport(
                "worker inventory identity changed".into(),
            )),
            None => Err(ProviderError::Transport(
                "worker inventory is not established".into(),
            )),
        }
    }

    fn allocate_id(&mut self) -> Result<u64, ProviderError> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| ProviderError::Transport("worker request id exhausted".into()))?;
        Ok(id)
    }
}

impl Drop for GhidraRustProvider {
    fn drop(&mut self) {
        if !self.closed && self.cleanup_failure.is_none() {
            if let Err(error) = self.child.cancel(1) {
                self.cleanup_failure = Some(error.message);
            }
        }
    }
}

fn absolute_environment_path(name: &str) -> Result<PathBuf, ProviderError> {
    let path = env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| ProviderError::InvalidConfiguration(format!("{name} is required")))?;
    if !path.is_absolute() {
        return Err(ProviderError::InvalidConfiguration(format!(
            "{name} must be absolute"
        )));
    }
    Ok(path)
}

fn validate_executable(path: &Path) -> Result<(), ProviderError> {
    let metadata = fs::metadata(path).map_err(|error| {
        ProviderError::InvalidConfiguration(format!("Cannot execute the Rust worker: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(ProviderError::InvalidConfiguration(
            "The configured worker is not a regular file.".into(),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "The configured worker is not executable.".into(),
            ));
        }
    }

    Ok(())
}

fn bounded_stderr(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_STDERR_BYTES)]).into_owned()
}
