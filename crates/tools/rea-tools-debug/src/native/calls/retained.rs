//! Readback of the files the LLDB bridge publishes in the runtime root.
//!
//! Compatibility owners: `src/native/LldbRetainedObservations.ts`
//! (`parseLldbObservationJournal`, `readLldbObservationJournal`,
//! `readPartialCapture`, `readBoundedPrefix`, `projectLldbPartialObservation`)
//! and `src/native/LldbReadbackFiles.ts` (`readTargetPid`). The journal and
//! capture files the unchanged bridge flushes survive tracer failure, so a
//! partial observation can be projected from them.
//!
//! Every readback opens a regular file in REA's private runtime root without
//! following symlinks; descriptors close on drop, so no readback descriptor
//! remains owned after a read.

use serde_json::{Map, Value, json};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

use super::input::ObservationInput;
use super::result::{CapturedOutput, normalize_event};

/// Maximum journal size enforced by the LLDB bridge.
const LLDB_OBSERVATION_JOURNAL_MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CAPTURE_BYTES: u64 = 1024 * 1024;
/// `String(Number.MAX_SAFE_INTEGER).length + 2`.
const TARGET_PID_FILE_MAX_BYTES: usize = 18;

/// Parsed JSONL journal (`ParsedLldbJournal`).
#[derive(Default)]
pub(crate) struct ParsedJournal {
    pub events: Vec<Value>,
    pub other_stops: Vec<String>,
    pub limitations: Vec<String>,
}

/// One readback failure with its Node-compatible reason text.
#[derive(Clone, Debug)]
pub(crate) struct ReadFailure {
    pub message: String,
}

/// `readBoundedPrefix` status.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrefixStatus {
    Complete,
    Eof,
    ReadFailure,
}

/// A bounded prefix read (`BoundedPrefixRead`).
pub(crate) struct PrefixRead {
    pub status: PrefixStatus,
    pub bytes: Vec<u8>,
    pub size: u64,
    pub failure: Option<ReadFailure>,
}

/// Node-style `fs` error text (`ENOENT: no such file or directory, open '…'`).
pub(crate) fn node_error(error: &std::io::Error, syscall: &str, path: &Path) -> ReadFailure {
    let (code, text) = match error.raw_os_error() {
        Some(libc::ENOENT) => ("ENOENT", "no such file or directory"),
        Some(libc::EACCES) => ("EACCES", "permission denied"),
        Some(libc::EISDIR) => ("EISDIR", "illegal operation on a directory"),
        Some(libc::ELOOP) => ("ELOOP", "too many symbolic links encountered"),
        Some(libc::EIO) => ("EIO", "i/o error"),
        _ => {
            return ReadFailure {
                message: format!("{error}, {syscall} '{}'", path.display()),
            };
        }
    };
    ReadFailure {
        message: format!("{code}: {text}, {syscall} '{}'", path.display()),
    }
}

/// Open one regular readback file without following a final symlink.
fn open_regular(path: &Path) -> Result<File, ReadFailure> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| node_error(&error, "open", path))?;
    let metadata = file
        .metadata()
        .map_err(|error| node_error(&error, "fstat", path))?;
    if !metadata.is_file() {
        return Err(ReadFailure {
            message: format!("Artifact path is not a regular file: {}", path.display()),
        });
    }
    Ok(file)
}

/// `readBoundedPrefix` over `min(size, maximum)` bytes, checking size first.
pub(crate) fn read_bounded_prefix(path: &Path, maximum: u64) -> Result<PrefixRead, ReadFailure> {
    let mut file = open_regular(path)?;
    let size = file
        .metadata()
        .map_err(|error| node_error(&error, "fstat", path))?
        .len();
    let requested = size.min(maximum) as usize;
    let mut bytes = vec![0_u8; requested];
    let mut read = 0;
    let mut failure = None;
    while read < requested {
        match file.read(&mut bytes[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => {
                failure = Some(node_error(&error, "read", path));
                break;
            }
        }
    }
    bytes.truncate(read);
    if let Some(failure) = failure {
        if read == 0 {
            return Err(failure);
        }
        return Ok(PrefixRead {
            status: PrefixStatus::ReadFailure,
            bytes,
            size,
            failure: Some(failure),
        });
    }
    Ok(PrefixRead {
        status: if read < requested {
            PrefixStatus::Eof
        } else {
            PrefixStatus::Complete
        },
        bytes,
        size,
        failure: None,
    })
}

/// Read one whole regular file (`file.readFile()`).
pub(crate) fn read_all(path: &Path) -> Result<Vec<u8>, ReadFailure> {
    let mut file = open_regular(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| node_error(&error, "read", path))?;
    Ok(bytes)
}

/// Write one private (0600) runtime file (`writeFile(path, text, { mode: 0o600 })`).
pub(crate) fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

/// `readTargetPid`: the single published decimal PID, if valid.
pub(crate) fn read_target_pid(path: &Path) -> Option<u32> {
    let mut file = open_regular(path).ok()?;
    let mut buffer = vec![0_u8; TARGET_PID_FILE_MAX_BYTES + 1];
    let mut length = 0;
    while length < buffer.len() {
        match file.read(&mut buffer[length..]) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    if length > TARGET_PID_FILE_MAX_BYTES {
        return None;
    }
    let text = String::from_utf8_lossy(&buffer[..length]);
    let text = text.trim();
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok()
}

/// `parseLldbObservationJournal`: parse completed JSONL rows, retaining valid
/// records around malformed ones.
pub(crate) fn parse_journal(bytes: &[u8]) -> ParsedJournal {
    let has_torn_tail = bytes.last().is_some_and(|byte| *byte != b'\n');
    let mut journal = ParsedJournal::default();
    let mut malformed = 0_u64;
    let mut first_malformed: Option<u64> = None;
    let mut start = 0;
    let mut row_number = 0_u64;
    while start < bytes.len() {
        let Some(offset) = bytes[start..].iter().position(|byte| *byte == b'\n') else {
            break;
        };
        let line = &bytes[start..start + offset];
        start += offset + 1;
        if line.is_empty() {
            continue;
        }
        row_number += 1;
        let row = std::str::from_utf8(line)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(text).ok());
        let accepted = match row
            .as_ref()
            .and_then(|row| row.get("kind").and_then(Value::as_str))
        {
            Some("event") => match row.as_ref().and_then(|row| row.get("event")) {
                Some(event) => normalize_event(event)
                    .map(|event| journal.events.push(event))
                    .is_some(),
                None => false,
            },
            Some("other-stop") => match row
                .as_ref()
                .and_then(|row| row.get("reason"))
                .and_then(Value::as_str)
            {
                Some(reason) => {
                    journal.other_stops.push(reason.to_owned());
                    true
                }
                None => false,
            },
            _ => false,
        };
        if !accepted {
            malformed += 1;
            first_malformed.get_or_insert(row_number);
        }
    }
    if malformed > 0 {
        journal.limitations.push(format!(
            "{malformed} observation journal row(s) were malformed or invalid and ignored (first at row {}).",
            first_malformed.unwrap_or(0)
        ));
    }
    if has_torn_tail {
        journal.limitations.push(
            "The final observation journal record was incomplete and was ignored.".to_owned(),
        );
    }
    journal
}

/// `readLldbObservationJournal`: the parsed journal, its read limitations
/// and any read failure that still yielded a prefix.
pub(crate) fn read_journal(
    path: &Path,
) -> Result<(ParsedJournal, Vec<String>, Option<ReadFailure>), ReadFailure> {
    let read = read_bounded_prefix(path, LLDB_OBSERVATION_JOURNAL_MAX_BYTES)?;
    let mut limitations = Vec::new();
    if read.size > LLDB_OBSERVATION_JOURNAL_MAX_BYTES {
        limitations.push(
            "The observation journal exceeded 8 MiB; only its bounded prefix was read.".to_owned(),
        );
    }
    if read.status == PrefixStatus::Eof {
        limitations.push(
            "The observation journal became shorter while being read; the available prefix was parsed."
                .to_owned(),
        );
    }
    if let Some(failure) = &read.failure {
        limitations.push(format!(
            "The observation journal read failed after {} bytes: {}",
            read.bytes.len(),
            failure.message
        ));
    }
    Ok((parse_journal(&read.bytes), limitations, read.failure))
}

/// `readPartialCapture`: a retained output prefix without an unreported total.
pub(crate) fn read_partial_capture(
    path: &Path,
) -> Result<(CapturedOutput, Vec<String>, Option<ReadFailure>), ReadFailure> {
    let read = read_bounded_prefix(path, MAX_CAPTURE_BYTES)?;
    let capture = CapturedOutput {
        text: String::from_utf8_lossy(&read.bytes).into_owned(),
        bytes: read.size.max(read.bytes.len() as u64),
        truncated: true,
        complete: false,
    };
    let mut limitations = Vec::new();
    if read.status == PrefixStatus::Eof {
        limitations.push(
            "A target output capture became shorter while being read; its retained prefix may be incomplete."
                .to_owned(),
        );
    }
    if let Some(failure) = &read.failure {
        limitations.push(format!(
            "A target output capture read failed after {} bytes: {}",
            read.bytes.len(),
            failure.message
        ));
    }
    Ok((capture, limitations, read.failure))
}

/// Target facts echoed into a partial observation (`target` without identity).
pub(crate) fn target_object(
    path: &str,
    sha256: &str,
    architecture: &str,
    input: &ObservationInput,
) -> Value {
    json!({
        "path": path,
        "sha256": sha256,
        "architecture": architecture,
        "arguments": input.arguments_value(),
        "environment": input.environment_object(),
        "working_directory": input.working_directory,
    })
}

/// `projectLldbPartialObservation`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn project_partial(
    target: Value,
    pid: Option<u32>,
    stdout: Option<&CapturedOutput>,
    stderr: Option<&CapturedOutput>,
    version: Option<&str>,
    journal: &ParsedJournal,
    journal_limitations: &[String],
    extra_limitations: &[String],
    reason: &str,
) -> Value {
    let mut limitations: Vec<String> = vec![
        "The LLDB run did not produce a complete native call observation result.".to_owned(),
        "The target SHA-256 identifies the selected artifact; LLDB did not verify the bytes loaded into the process.".to_owned(),
        "Captured output byte counts are observed lower bounds because LLDB did not report final stream counters.".to_owned(),
    ];
    limitations.extend(journal.limitations.iter().cloned());
    limitations.extend(journal_limitations.iter().cloned());
    limitations.extend(extra_limitations.iter().cloned());
    if pid.is_none() {
        limitations.push("The target PID was unavailable.".to_owned());
    }
    if stdout.is_none() {
        limitations.push("The target stdout capture was unavailable.".to_owned());
    }
    if stderr.is_none() {
        limitations.push("The target stderr capture was unavailable.".to_owned());
    }
    let mut debugger = Map::new();
    debugger.insert("version".into(), version.map_or(Value::Null, Value::from));
    json!({
        "kind": "native-call-observation",
        "target": target,
        "process": {
            "pid": pid,
            "stdout": stdout.map_or(Value::Null, CapturedOutput::to_value),
            "stderr": stderr.map_or(Value::Null, CapturedOutput::to_value),
            "other_stops": journal.other_stops,
        },
        "debugger": Value::Object(debugger),
        "events": journal.events,
        "coverage": { "status": "partial", "reason": reason },
        "limitations": limitations,
    })
}
