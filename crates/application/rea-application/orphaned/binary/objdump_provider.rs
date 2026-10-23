//! Bounded host execution adapter for GNU objdump.
//!
//! Admission owns caller-path and artifact checks. Execution owns only the
//! selected objdump process and bounded capture. Normalization delegates to
//! the objdump inspection module, which preserves provider raw observations
//! without treating objdump text as a stable parser format.

use crate::binary::objdump_inspection::{
    self, CapturedObjdumpOutput, CompletionStatus, ObjdumpOperation, ObjdumpRequest,
};
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const OPERATION: &str = "inspect_with_objdump";
pub const MAX_COMBINED_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// Execute the configured objdump command and retain its bounded observation.
pub fn inspect(input: &Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    let executable = std::env::var_os("REA_OBJDUMP_COMMAND")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("objdump"));
    inspect_with_executable(input, &executable, cancellation)
}

/// Execute a caller-selected objdump executable.
///
/// The executable is configuration, while the artifact and objdump operation
/// remain caller-selected input. No shell is used and the artifact is never
/// launched as a process.
pub fn inspect_with_executable(
    input: &Value,
    executable: &Path,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    let admitted = admit(input, executable)?;
    let capture = execute(&admitted, cancellation)?;
    normalize(admitted, capture)
}

#[derive(Clone, Debug)]
struct AdmittedRequest {
    request: ObjdumpRequest,
    artifact_path: Option<PathBuf>,
    executable: PathBuf,
    arguments: Vec<String>,
    artifact_sha256_before: Option<String>,
}

fn admit(input: &Value, executable: &Path) -> Result<AdmittedRequest, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("objdump input must be an object"))?;
    let request: ObjdumpRequest = serde_json::from_value(
        object
            .get("request")
            .cloned()
            .unwrap_or_else(|| input.clone()),
    )
    .or_else(|_| serde_json::from_value(input.clone()))
    .map_err(|_| invalid("invalid objdump request"))?;
    objdump_inspection::validate_request(&request)?;

    if executable.as_os_str().is_empty() || executable.to_string_lossy().contains('\0') {
        return Err(invalid("objdump executable must be non-empty and NUL-free"));
    }

    let artifact_path = request.path.as_deref().map(absolute_path).transpose()?;
    let artifact_sha256_before = match artifact_path.as_ref() {
        Some(path) => Some(validate_artifact(path)?),
        None => None,
    };
    let arguments = command_arguments(&request, artifact_path.as_deref());

    Ok(AdmittedRequest {
        request,
        artifact_path,
        executable: executable.to_owned(),
        arguments,
        artifact_sha256_before,
    })
}

fn execute(
    admitted: &AdmittedRequest,
    cancellation: &Cancellation,
) -> Result<CapturedObjdumpOutput, Failure> {
    if cancellation.reason().is_some() {
        return Err(cancelled());
    }

    let mut child = Command::new(&admitted.executable)
        .args(&admitted.arguments)
        .env("DEBUGINFOD_URLS", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| unavailable(&format!("Unable to start objdump: {error}")))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| unavailable("objdump stdout pipe was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| unavailable("objdump stderr pipe was unavailable"))?;
    let stdout_reader = thread::spawn(|| read_bounded(stdout));
    let stderr_reader = thread::spawn(|| read_bounded(stderr));
    let started = Instant::now();
    let mut terminated = false;
    let status = loop {
        if cancellation.reason().is_some() || started.elapsed() >= TIMEOUT {
            terminated = true;
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(unavailable(&format!("Unable to observe objdump: {error}")));
            }
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| unavailable("objdump stdout reader failed"))?
        .map_err(|error| unavailable(&format!("Unable to read objdump stdout: {error}")))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| unavailable("objdump stderr reader failed"))?
        .map_err(|error| unavailable(&format!("Unable to read objdump stderr: {error}")))?;
    let mut stdout_bytes = stdout.bytes;
    let mut stderr_bytes = stderr.bytes;
    let output_truncated = stdout.truncated
        || stderr.truncated
        || stdout_bytes.len().saturating_add(stderr_bytes.len()) > MAX_COMBINED_OUTPUT_BYTES;
    if output_truncated {
        truncate_combined_output(&mut stdout_bytes, &mut stderr_bytes);
    }

    if terminated {
        return Err(if cancellation.reason().is_some() {
            cancelled()
        } else {
            timeout()
        });
    }

    let artifact_sha256_after = admitted
        .artifact_path
        .as_ref()
        .and_then(|path| digest_artifact(path).ok());
    let artifact_changed = admitted
        .artifact_sha256_before
        .as_ref()
        .zip(artifact_sha256_after.as_ref())
        .map(|(before, after)| before != after);
    let (stdout, stdout_invalid_utf8) = decode(&stdout_bytes);
    let (stderr, stderr_invalid_utf8) = decode(&stderr_bytes);
    let (exit_code, signal) = status_facts(status);

    Ok(CapturedObjdumpOutput {
        stdout,
        stderr,
        exit_code,
        signal,
        output_truncated,
        completion_status: if output_truncated {
            CompletionStatus::Unknown
        } else {
            CompletionStatus::Complete
        },
        artifact_sha256_after,
        artifact_changed,
        artifact_sha256_before: admitted.artifact_sha256_before.clone(),
        provider_executable: Some(admitted.executable.to_string_lossy().into_owned()),
        command_arguments: Some(admitted.arguments.clone()),
        stdout_invalid_utf8,
        stderr_invalid_utf8,
        output_budget_bytes: Some(MAX_COMBINED_OUTPUT_BYTES as u64),
    })
}

fn truncate_combined_output(stdout: &mut Vec<u8>, stderr: &mut Vec<u8>) {
    if stdout.len() >= MAX_COMBINED_OUTPUT_BYTES {
        stdout.truncate(MAX_COMBINED_OUTPUT_BYTES);
        stderr.clear();
        return;
    }
    let remaining = MAX_COMBINED_OUTPUT_BYTES - stdout.len();
    stderr.truncate(remaining);
}

fn normalize(
    admitted: AdmittedRequest,
    capture: CapturedObjdumpOutput,
) -> Result<Value, Failure> {
    let input = json!({
        "request": admitted.request,
        "capture": capture,
    });
    objdump_inspection::inspect_value(&input)
}

#[derive(Debug)]
struct BoundedBytes {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_bounded<R: Read>(mut reader: R) -> std::io::Result<BoundedBytes> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; READ_CHUNK_BYTES];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_COMBINED_OUTPUT_BYTES.saturating_sub(bytes.len());
        let retained = read.min(remaining);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained != read;
        if truncated {
            break;
        }
    }
    Ok(BoundedBytes { bytes, truncated })
}

fn command_arguments(request: &ObjdumpRequest, artifact_path: Option<&Path>) -> Vec<String> {
    let mut arguments = match request.operation {
        ObjdumpOperation::Architectures => vec!["-i".into()],
        ObjdumpOperation::FileHeaders => vec!["-f".into()],
        ObjdumpOperation::SectionHeaders => vec!["-h".into()],
        ObjdumpOperation::Symbols => vec!["-t".into()],
        ObjdumpOperation::Relocations => vec!["-r".into()],
        ObjdumpOperation::Dwarf => vec![
            "-W".into(),
            if request.follow_debug_links {
                "-WK"
            } else {
                "-WN"
            }
            .into(),
        ],
        ObjdumpOperation::Disassemble => request
            .symbol
            .as_ref()
            .map(|symbol| vec![format!("--disassemble={symbol}")])
            .unwrap_or_else(|| vec!["-d".into()]),
        ObjdumpOperation::DisassembleAll => vec!["-D".into()],
    };
    if let Some(path) = artifact_path {
        arguments.push(path.to_string_lossy().into_owned());
    }
    arguments
}

fn validate_artifact(path: &Path) -> Result<String, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| invalid(&format!("Unable to inspect selected artifact: {error}")))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("selected artifact must be a regular non-symlink file"));
    }
    digest_artifact(path)
        .map_err(|error| invalid(&format!("Unable to hash selected artifact: {error}")))
}

fn digest_artifact(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; READ_CHUNK_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn absolute_path(path: &str) -> Result<PathBuf, Failure> {
    if path.is_empty() || path.contains('\0') {
        return Err(invalid("artifact path must be non-empty and NUL-free"));
    }
    let path = Path::new(path);
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .map_err(|error| invalid(&format!("Unable to resolve artifact path: {error}")))
    }
}

fn decode(bytes: &[u8]) -> (String, bool) {
    match String::from_utf8(bytes.to_owned()) {
        Ok(text) => (text, false),
        Err(error) => (String::from_utf8_lossy(error.as_bytes()).into_owned(), true),
    }
}

#[cfg(unix)]
fn status_facts(status: Option<std::process::ExitStatus>) -> (Option<i64>, Option<String>) {
    use std::os::unix::process::ExitStatusExt;
    let Some(status) = status else {
        return (None, None);
    };
    (
        status.code().map(i64::from),
        status.signal().map(|signal| signal.to_string()),
    )
}

#[cfg(not(unix))]
fn status_facts(status: Option<std::process::ExitStatus>) -> (Option<i64>, Option<String>) {
    let Some(status) = status else {
        return (None, None);
    };
    (status.code().map(i64::from), None)
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a caller-selected artifact and bounded objdump operation.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn unavailable(reason: &str) -> Failure {
    Failure::new(
        "capability_unavailable",
        "capability_unavailable",
        reason.into(),
        true,
        "Configure a working GNU objdump executable and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn cancelled() -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        "Objdump inspection was cancelled.".into(),
        false,
        "Retry the operation if the observation is still needed.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn timeout() -> Failure {
    Failure::new(
        "timeout",
        "timeout",
        "Objdump inspection exceeded its execution deadline.".into(),
        true,
        "Retry with a smaller artifact or a narrower operation.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
