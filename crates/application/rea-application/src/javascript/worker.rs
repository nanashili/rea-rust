//! Owned subprocess boundary for JavaScript source analysis.
//!
//! A worker is the unit of resource ownership for one source file. The parent
//! never performs the expensive parse in its own process when a worker is
//! requested; it owns the child until the child exits or cleanup settles.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

pub const WORKER_ARGUMENT: &str = "--rea-javascript-worker";
const WORKER_HEAP_ARGUMENT_PREFIX: &str = "--rea-javascript-worker-max-heap-mb=";
pub const MEMORY_BUDGET_EXIT_CODE: u32 = 122;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone, Debug)]
pub struct WorkerLimits {
    pub max_heap_mb: Option<u64>,
    pub timeout: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerRequest {
    #[serde(default)]
    pub max_heap_mb: Option<u64>,
    #[serde(default)]
    pub node_budget: usize,
    #[serde(default)]
    pub unknown_budget: usize,
    #[serde(default)]
    pub file: Option<WorkerFileMetadata>,
    pub source: String,
    pub path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerFileMetadata {
    pub path: String,
    pub container_sha256: String,
    pub sha256: String,
    pub bytes: u64,
    pub inventory_artifact_id: String,
    pub kind: String,
    pub unpacked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub static_analysis: Box<RawValue>,
    pub semantic_ir: Option<Box<RawValue>>,
    #[serde(default)]
    pub semantic_projection: Option<Box<RawValue>>,
    /// Small facts needed by aggregate coverage after the full IR is dropped.
    #[serde(default)]
    pub semantic_metadata: Option<Box<RawValue>>,
    #[serde(default)]
    pub semantic_failure: Option<WorkerSemanticFailure>,
}

/// A semantic phase can fail after the static checkpoint has been emitted.
/// Keeping this separate from [`WorkerFailure`] lets the parent retain the
/// static facts while reporting the semantic failure as an owned result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerSemanticFailure {
    pub phase: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
struct WorkerCheckpoint {
    static_analysis: Box<RawValue>,
}

#[derive(Serialize)]
struct WorkerCheckpointFrame<'a> {
    static_analysis: &'a RawValue,
}

#[derive(Clone, Debug)]
pub enum WorkerFailure {
    ResourceConstraint {
        requested_mb: u64,
        reason: String,
    },
    Launch(String),
    Timeout {
        timeout_ms: u128,
    },
    Cancelled,
    Output(String),
    Protocol(String),
    Partial {
        primary: Box<Self>,
        static_analysis: Box<RawValue>,
    },
    Cleanup {
        primary: Box<Self>,
        cleanup: String,
    },
}

impl std::fmt::Display for WorkerFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResourceConstraint {
                requested_mb,
                reason,
            } => write!(formatter, "max_heap_mb={requested_mb} exhausted: {reason}"),
            Self::Launch(reason) => {
                write!(formatter, "could not launch JavaScript worker: {reason}")
            }
            Self::Timeout { timeout_ms } => {
                write!(formatter, "JavaScript worker exceeded {timeout_ms}ms")
            }
            Self::Cancelled => formatter.write_str("JavaScript worker was cancelled"),
            Self::Output(reason) => write!(formatter, "JavaScript worker output failed: {reason}"),
            Self::Protocol(reason) => {
                write!(formatter, "invalid JavaScript worker response: {reason}")
            }
            Self::Cleanup { primary, cleanup } => {
                write!(formatter, "{primary} (cleanup failed: {cleanup})")
            }
            Self::Partial {
                primary,
                static_analysis: _,
            } => write!(formatter, "{primary} (static analysis checkpoint retained)"),
        }
    }
}

impl std::error::Error for WorkerFailure {}

impl WorkerFailure {
    pub fn is_cancelled(&self) -> bool {
        matches!(self.primary_failure(), Self::Cancelled)
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self.primary_failure(), Self::Timeout { .. })
    }

    pub fn is_resource_constraint(&self) -> bool {
        matches!(self.primary_failure(), Self::ResourceConstraint { .. })
    }

    pub fn static_checkpoint(&self) -> Option<&RawValue> {
        match self {
            Self::Partial {
                static_analysis, ..
            } => Some(static_analysis),
            Self::Cleanup { primary, .. } => primary.static_checkpoint(),
            _ => None,
        }
    }

    pub fn primary_failure(&self) -> &Self {
        match self {
            Self::Cleanup { primary, .. } => primary.primary_failure(),
            Self::Partial { primary, .. } => primary.primary_failure(),
            _ => self,
        }
    }
}

/// Run one source through the standalone native worker.
pub fn analyze_source_with_worker(
    request: &WorkerRequest,
    limits: &WorkerLimits,
    mut cancelled: impl FnMut() -> bool,
) -> Result<WorkerResponse, WorkerFailure> {
    let started = Instant::now();
    if started.elapsed() >= limits.timeout {
        return Err(WorkerFailure::Timeout {
            timeout_ms: limits.timeout.as_millis(),
        });
    }
    if request.source.len() > MAX_INPUT_BYTES {
        return Err(WorkerFailure::Protocol(
            "JavaScript worker request exceeded the bounded input budget".to_owned(),
        ));
    }
    let request_wire = WorkerRequestWire {
        max_heap_mb: limits.max_heap_mb,
        node_budget: request.node_budget,
        unknown_budget: request.unknown_budget,
        file: request.file.as_ref(),
        source: &request.source,
        path: request.path.as_deref(),
    };
    let request_bytes = serialize_bounded_request(&request_wire)?;

    let executable =
        std::env::current_exe().map_err(|error| WorkerFailure::Launch(error.to_string()))?;
    let mut child = OwnedChildProcess::launch_with_capture_limit(
        ChildLaunchSpec {
            executable,
            arguments: worker_arguments(limits.max_heap_mb),
            working_directory: None::<PathBuf>,
            protocol_stdin: true,
            limits: rea_host::process::windows::job::WindowsJobLimits {
                memory_bytes: limits
                    .max_heap_mb
                    .map(|value| value.saturating_mul(1024 * 1024)),
                cpu_seconds: None,
            },
        },
        MAX_OUTPUT_BYTES,
    )
    .map_err(|error| WorkerFailure::Launch(error.to_string()))?;

    if started.elapsed() >= limits.timeout {
        return Err(interrupted_worker_failure(
            &mut child,
            124,
            WorkerFailure::Timeout {
                timeout_ms: limits.timeout.as_millis(),
            },
        ));
    }
    for chunk in request_bytes.chunks(64 * 1024) {
        if started.elapsed() >= limits.timeout {
            return Err(interrupted_worker_failure(
                &mut child,
                124,
                WorkerFailure::Timeout {
                    timeout_ms: limits.timeout.as_millis(),
                },
            ));
        }
        if let Err(error) = child.write_input(chunk) {
            return Err(interrupted_worker_failure(
                &mut child,
                125,
                WorkerFailure::Launch(error.to_string()),
            ));
        }
        if cancelled() {
            return Err(interrupted_worker_failure(
                &mut child,
                125,
                WorkerFailure::Cancelled,
            ));
        }
        if started.elapsed() >= limits.timeout {
            return Err(interrupted_worker_failure(
                &mut child,
                124,
                WorkerFailure::Timeout {
                    timeout_ms: limits.timeout.as_millis(),
                },
            ));
        }
    }
    child.close_input();

    if started.elapsed() >= limits.timeout {
        return Err(interrupted_worker_failure(
            &mut child,
            124,
            WorkerFailure::Timeout {
                timeout_ms: limits.timeout.as_millis(),
            },
        ));
    }

    let exit = loop {
        if cancelled() {
            return Err(interrupted_worker_failure(
                &mut child,
                125,
                WorkerFailure::Cancelled,
            ));
        }
        if started.elapsed() >= limits.timeout {
            return Err(interrupted_worker_failure(
                &mut child,
                124,
                WorkerFailure::Timeout {
                    timeout_ms: limits.timeout.as_millis(),
                },
            ));
        }
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                return Err(interrupted_worker_failure(
                    &mut child,
                    125,
                    WorkerFailure::Output(error.to_string()),
                ));
            }
        };
        if let Some(exit) = status {
            break exit;
        }
        std::thread::sleep(POLL_INTERVAL);
    };
    let output = child
        .drain_output()
        .map_err(|error| WorkerFailure::Output(error.to_string()))?;
    if output.stdout.len().saturating_add(output.stderr.len()) > MAX_OUTPUT_BYTES
        || output.output_incomplete
    {
        return Err(with_checkpoint(
            WorkerFailure::Output("worker response exceeded the bounded output budget".to_owned()),
            &output.stdout,
        ));
    }
    if exit.code == MEMORY_BUDGET_EXIT_CODE {
        return Err(with_checkpoint(
            WorkerFailure::ResourceConstraint {
                requested_mb: limits.max_heap_mb.unwrap_or_default(),
                reason: "native worker Rust heap budget was exhausted".to_owned(),
            },
            &output.stdout,
        ));
    }
    if exit.code != 0 {
        let failure = WorkerFailure::Protocol(format!(
            "worker exited with code {}{}",
            exit.code,
            exit.signal
                .map(|signal| format!(" after signal {signal}"))
                .unwrap_or_default()
        ));
        let failure = if output.stderr.is_empty() {
            failure
        } else {
            WorkerFailure::Protocol(format!(
                "{failure}; stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        };
        return Err(with_checkpoint(failure, &output.stdout));
    }
    parse_worker_response(&output.stdout)
}

fn interrupted_worker_failure(
    child: &mut OwnedChildProcess,
    exit_code: u32,
    primary: WorkerFailure,
) -> WorkerFailure {
    let cleanup_error = child.cancel(exit_code).err().map(|error| error.to_string());
    let drained_output = child.drain_output();
    let drain_error = drained_output.as_ref().err().map(|error| error.to_string());
    let cleanup = match (cleanup_error, drain_error) {
        (None, None) => None,
        (Some(cancel), None) => Some(cancel),
        (None, Some(drain)) => Some(format!("output drain failed: {drain}")),
        (Some(cancel), Some(drain)) => Some(format!("{cancel}; output drain failed: {drain}")),
    };
    let failure = match cleanup {
        Some(cleanup) => WorkerFailure::Cleanup {
            primary: Box::new(primary),
            cleanup,
        },
        None => primary,
    };
    match drained_output {
        Ok(output) => with_checkpoint(failure, &output.stdout),
        Err(_) => failure,
    }
}

fn with_checkpoint(failure: WorkerFailure, output: &[u8]) -> WorkerFailure {
    match parse_checkpoint(output) {
        Some(static_analysis) => WorkerFailure::Partial {
            primary: Box::new(failure),
            static_analysis,
        },
        None => failure,
    }
}

fn parse_checkpoint(output: &[u8]) -> Option<Box<RawValue>> {
    output
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<WorkerCheckpoint>(line).ok())
        .next()
        .map(|checkpoint| checkpoint.static_analysis)
}

fn parse_worker_response(output: &[u8]) -> Result<WorkerResponse, WorkerFailure> {
    output
        .split(|byte| *byte == b'\n')
        .rev()
        .find(|line| !line.is_empty())
        .ok_or_else(|| WorkerFailure::Protocol("worker response was empty".to_owned()))
        .and_then(|line| {
            serde_json::from_slice(line).map_err(|error| WorkerFailure::Protocol(error.to_string()))
        })
}

/// Entry point used by the production executable's private worker dispatch.
pub fn run_worker_from_stdin() -> i32 {
    run_worker_from_stdin_with_limit(None, |_| {})
}

pub fn run_worker_from_stdin_with_setup(setup: impl FnOnce(Option<u64>)) -> i32 {
    run_worker_from_stdin_with_limit(None, setup)
}

pub fn run_worker_from_stdin_with_limit(
    max_heap_mb: Option<u64>,
    setup: impl FnOnce(Option<u64>),
) -> i32 {
    let input = match read_worker_input(max_heap_mb, setup) {
        Ok(input) => input,
        Err(_) => return 2,
    };
    if input.len() > MAX_INPUT_BYTES {
        return 2;
    }

    let request: WorkerRequest = match serde_json::from_slice(&input) {
        Ok(request) => request,
        Err(_) => return 2,
    };
    let mut checkpoint_error = false;
    let response = super::analysis::analyze_source_for_worker_with_checkpoint(
        &request.source,
        request.path.as_deref(),
        request.node_budget,
        request.unknown_budget,
        request.file.as_ref(),
        |static_analysis| {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            let checkpoint_bytes = serde_json::to_vec(&WorkerCheckpointFrame { static_analysis });
            if checkpoint_bytes
                .ok()
                .and_then(|bytes| stdout.write_all(&bytes).ok())
                .and_then(|_| stdout.write_all(b"\n").ok())
                .and_then(|_| stdout.flush().ok())
                .is_none()
            {
                checkpoint_error = true;
            }
        },
    );
    if checkpoint_error {
        return 2;
    }
    match serde_json::to_vec(&response) {
        Ok(bytes) => {
            print!("{}", String::from_utf8_lossy(&bytes));
            0
        }
        Err(_) => 2,
    }
}

fn read_worker_input(
    max_heap_mb: Option<u64>,
    setup: impl FnOnce(Option<u64>),
) -> std::io::Result<Vec<u8>> {
    let mut input = Vec::with_capacity(4096);
    let mut prefix = [0_u8; 1024];
    let mut stdin = std::io::stdin().lock();

    while input.len() < prefix.len() {
        let count = stdin.read(&mut prefix[input.len()..])?;
        if count == 0 {
            break;
        }
        input.extend_from_slice(&prefix[input.len()..input.len() + count]);
    }

    setup(max_heap_mb);

    if input.len() < prefix.len() {
        return Ok(input);
    }

    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let count = stdin.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if input.len().saturating_add(count) > MAX_INPUT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "worker request exceeded the bounded input budget",
            ));
        }
        input.extend_from_slice(&chunk[..count]);
    }
    Ok(input)
}

#[derive(Serialize)]
struct WorkerRequestWire<'a> {
    max_heap_mb: Option<u64>,
    node_budget: usize,
    unknown_budget: usize,
    file: Option<&'a WorkerFileMetadata>,
    source: &'a str,
    path: Option<&'a str>,
}

/// Serialize once into a byte counter before allocating the request buffer.
///
/// JSON escaping can expand source considerably, so a multiplier-based estimate
/// would reject valid requests based on a guess. The counter uses the same
/// serializer and wire value as the retained pass, making the admission check
/// exact while keeping the parent bounded before the second allocation.
fn serialize_bounded_request(request: &WorkerRequestWire<'_>) -> Result<Vec<u8>, WorkerFailure> {
    let mut counter = CountingWriter::default();
    serde_json::to_writer(&mut counter, request)
        .map_err(|error| WorkerFailure::Protocol(error.to_string()))?;

    if counter.bytes_written > MAX_INPUT_BYTES {
        return Err(WorkerFailure::Protocol(
            "expanded JavaScript worker request exceeded the bounded input budget".to_owned(),
        ));
    }

    let mut request_bytes = Vec::with_capacity(counter.bytes_written);
    serde_json::to_writer(&mut request_bytes, request)
        .map_err(|error| WorkerFailure::Protocol(error.to_string()))?;

    if request_bytes.len() != counter.bytes_written {
        return Err(WorkerFailure::Protocol(
            "worker request size changed during bounded serialization".to_owned(),
        ));
    }

    Ok(request_bytes)
}

#[derive(Default)]
struct CountingWriter {
    bytes_written: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes_written = self.bytes_written.checked_add(bytes.len()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "worker request size overflow",
            )
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn worker_arguments(max_heap_mb: Option<u64>) -> Vec<OsString> {
    let mut arguments = vec![OsString::from(WORKER_ARGUMENT)];
    if let Some(max_heap_mb) = max_heap_mb {
        arguments.push(OsString::from(format!(
            "{WORKER_HEAP_ARGUMENT_PREFIX}{max_heap_mb}"
        )));
    }
    arguments
}

pub fn max_heap_mb_from_argument(argument: &str) -> Option<u64> {
    argument
        .strip_prefix(WORKER_HEAP_ARGUMENT_PREFIX)?
        .parse()
        .ok()
}
