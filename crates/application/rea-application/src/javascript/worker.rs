//! Owned subprocess boundary for JavaScript source analysis.
//!
//! A worker is the unit of resource ownership for one source file. The parent
//! never performs the expensive parse in its own process when a worker is
//! requested; it owns the child until the child exits or cleanup settles.

use std::cell::RefCell;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

mod transport;

use transport::{parse_checkpoint, parse_worker_response, write_checkpoint, write_worker_response};

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

/// Resource policy shared by the subprocess job and its response admission.
/// The decoded byte limit does not bound the parent's materialized JSON heap.
struct WorkerMemoryPolicy {
    job_memory_bytes: Option<u64>,
    decoded_response_bytes: usize,
}

impl WorkerMemoryPolicy {
    fn from_heap_limit(max_heap_mb: Option<u64>) -> Result<Self, WorkerFailure> {
        let Some(megabytes) = max_heap_mb else {
            return Ok(Self {
                job_memory_bytes: None,
                decoded_response_bytes: MAX_OUTPUT_BYTES,
            });
        };

        let invalid = || {
            WorkerFailure::Protocol(format!(
                "invalid worker heap budget: max_heap_mb={megabytes} must be positive and addressable"
            ))
        };
        if megabytes == 0 {
            return Err(invalid());
        }
        let memory_bytes = megabytes.checked_mul(1024 * 1024).ok_or_else(invalid)?;
        let decoded_response_bytes = usize::try_from(memory_bytes / 4).map_err(|_| invalid())?;

        Ok(Self {
            job_memory_bytes: Some(memory_bytes),
            decoded_response_bytes,
        })
    }
}

/// Keep the first interruption authoritative through execution and finalization.
struct WorkerBudget<'a> {
    started: Instant,
    timeout: Duration,
    cancelled: &'a mut dyn FnMut() -> bool,
    interruption: Option<WorkerFailure>,
}

impl<'a> WorkerBudget<'a> {
    fn new(timeout: Duration, cancelled: &'a mut dyn FnMut() -> bool) -> Self {
        Self {
            started: Instant::now(),
            timeout,
            cancelled,
            interruption: None,
        }
    }

    fn interruption(&mut self) -> Option<WorkerFailure> {
        if self.interruption.is_none() {
            self.interruption = if (self.cancelled)() {
                Some(WorkerFailure::Cancelled)
            } else if self.started.elapsed() >= self.timeout {
                Some(WorkerFailure::Timeout {
                    timeout_ms: self.timeout.as_millis(),
                })
            } else {
                None
            };
        }
        self.interruption.clone()
    }

    fn check(&mut self) -> Result<(), WorkerFailure> {
        self.interruption().map_or(Ok(()), Err)
    }
}

/// Run one source through the standalone native worker.
pub fn analyze_source_with_worker(
    request: &WorkerRequest,
    limits: &WorkerLimits,
    mut cancelled: impl FnMut() -> bool,
) -> Result<WorkerResponse, WorkerFailure> {
    let mut budget = WorkerBudget::new(limits.timeout, &mut cancelled);
    budget.check()?;
    let memory = WorkerMemoryPolicy::from_heap_limit(limits.max_heap_mb)?;
    let request_bytes = prepare_worker_request(request, limits.max_heap_mb)?;
    budget.check()?;

    let executable =
        std::env::current_exe().map_err(|error| WorkerFailure::Launch(error.to_string()))?;
    let mut child = OwnedChildProcess::launch_with_capture_limit(
        ChildLaunchSpec {
            executable,
            arguments: worker_arguments(limits.max_heap_mb),
            working_directory: None::<PathBuf>,
            protocol_stdin: true,
            limits: rea_host::process::windows::job::WindowsJobLimits {
                memory_bytes: memory.job_memory_bytes,
                cpu_seconds: None,
            },
        },
        MAX_OUTPUT_BYTES,
    )
    .map_err(|error| WorkerFailure::Launch(error.to_string()))?;

    let execution = send_worker_request(&mut child, request_bytes, &mut budget)
        .and_then(|()| wait_for_worker_exit(&mut child, &mut budget));
    let exit = match execution {
        Ok(exit) => exit,
        Err(failure) => return Err(interrupted_worker_failure(&mut child, 125, failure)),
    };
    if let Err(error) = child.wait() {
        return Err(interrupted_worker_failure(
            &mut child,
            125,
            WorkerFailure::Output(format!("worker settlement failed: {error}")),
        ));
    }

    let output = {
        let budget = RefCell::new(&mut budget);
        child.drain_output_with(|| budget.borrow_mut().interruption().is_some())
    }
    .map_err(|error| WorkerFailure::Output(error.to_string()))?;
    let result = budget.check().and_then(|()| {
        validate_worker_output(&output, &exit, limits.max_heap_mb)?;
        parse_worker_response(&output.stdout, memory.decoded_response_bytes, || {
            budget.interruption()
        })
    });

    result.map_err(|failure| with_checkpoint(failure, &output.stdout))
}

fn prepare_worker_request(
    request: &WorkerRequest,
    max_heap_mb: Option<u64>,
) -> Result<Vec<u8>, WorkerFailure> {
    if request.source.len() > MAX_INPUT_BYTES {
        return Err(WorkerFailure::Protocol(
            "JavaScript worker request exceeded the bounded input budget".to_owned(),
        ));
    }

    serialize_bounded_request(&WorkerRequestWire {
        max_heap_mb,
        node_budget: request.node_budget,
        unknown_budget: request.unknown_budget,
        file: request.file.as_ref(),
        source: &request.source,
        path: request.path.as_deref(),
    })
}

fn send_worker_request(
    child: &mut OwnedChildProcess,
    request_bytes: Vec<u8>,
    budget: &mut WorkerBudget<'_>,
) -> Result<(), WorkerFailure> {
    for chunk in request_bytes.chunks(64 * 1024) {
        budget.check()?;
        child
            .write_input(chunk)
            .map_err(|error| WorkerFailure::Launch(error.to_string()))?;
        budget.check()?;
    }
    child.close_input();
    Ok(())
}

fn wait_for_worker_exit(
    child: &mut OwnedChildProcess,
    budget: &mut WorkerBudget<'_>,
) -> Result<rea_host::process::launcher::ChildExit, WorkerFailure> {
    loop {
        budget.check()?;
        let status = child
            .try_wait()
            .map_err(|error| WorkerFailure::Output(error.to_string()))?;
        if let Some(exit) = status {
            return Ok(exit);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn validate_worker_output(
    output: &rea_host::process::launcher::ChildOutput,
    exit: &rea_host::process::launcher::ChildExit,
    max_heap_mb: Option<u64>,
) -> Result<(), WorkerFailure> {
    if output.stdout.len().saturating_add(output.stderr.len()) > MAX_OUTPUT_BYTES
        || output.output_incomplete
    {
        return Err(WorkerFailure::Output(
            "worker response exceeded the bounded output budget".to_owned(),
        ));
    }
    if exit.code == MEMORY_BUDGET_EXIT_CODE {
        return Err(WorkerFailure::ResourceConstraint {
            requested_mb: max_heap_mb.unwrap_or_default(),
            reason: "native worker Rust heap budget was exhausted".to_owned(),
        });
    }
    if exit.code == 0 && exit.signal.is_none() {
        return Ok(());
    }

    let signal = exit
        .signal
        .map(|signal| format!(" after signal {signal}"))
        .unwrap_or_default();
    let stderr = if output.stderr.is_empty() {
        String::new()
    } else {
        format!("; stderr: {}", String::from_utf8_lossy(&output.stderr))
    };
    Err(WorkerFailure::Protocol(format!(
        "worker exited with code {}{signal}{stderr}",
        exit.code
    )))
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
    let memory = match WorkerMemoryPolicy::from_heap_limit(max_heap_mb) {
        Ok(memory) => memory,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
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
    // The request owns its decoded source. Release the wire buffer before
    // building the AST and semantic facts within the same heap budget.
    drop(input);

    let mut checkpoint_error = None;
    let response = super::analysis::analyze_source_for_worker_with_checkpoint(
        &request.source,
        request.path.as_deref(),
        request.node_budget,
        request.unknown_budget,
        request.file.as_ref(),
        |static_analysis| {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            if let Err(error) = write_checkpoint(&mut stdout, static_analysis) {
                checkpoint_error = Some(error);
            }
        },
    );
    if let Some(error) = checkpoint_error {
        eprintln!("JavaScript worker checkpoint failed: {error}");
        return 2;
    }
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    match write_worker_response(&mut stdout, &response, memory.decoded_response_bytes) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("JavaScript worker response failed: {error}");
            2
        }
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
            std::io::Error::new(std::io::ErrorKind::InvalidData, "worker JSON size overflow")
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
