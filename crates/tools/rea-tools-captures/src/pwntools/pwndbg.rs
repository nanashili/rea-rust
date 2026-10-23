//! Core-only debugger context through caller-supplied GDB/pwndbg.
//!
//! Compatibility owners: `src/native/pwndbg/PwndbgCoreContext.ts` and
//! `src/native/pwndbg/CoreFileMappingAuthority.ts`.
use crate::artifact::{self, ReaderReason};
use crate::node::{self, AccessMode, FsError};
use crate::process::ProcessSnapshot;
use crate::producer;
use crate::pwntools::decoder::OwnedCommand;
use crate::pwntools::layout::hex_to_u64;
use crate::pwntools::release;
use rea_core::analysis_error::{AnalysisError, CapturedOutput};
use rea_core::cancellation::Cancellation;
use serde_json::{Value, json};
use std::collections::HashMap;

const OPERATION: &str = "inspect_recorded_crash";
const PROVIDER: &str = "pwndbg-core";

/// `recordedCrashStageOutput`: preserve both stages' text and truncation.
pub fn stage_output(basic: &CapturedOutput, debugger: Option<&CapturedOutput>) -> CapturedOutput {
    match debugger {
        None => basic.clone(),
        Some(debugger) => CapturedOutput {
            stdout: format!(
                "[core decoder]\n{}\n[debugger]\n{}",
                basic.stdout, debugger.stdout
            ),
            stderr: format!(
                "[core decoder]\n{}\n[debugger]\n{}",
                basic.stderr, debugger.stderr
            ),
            truncated: basic.truncated || debugger.truncated,
            stdout_bytes: None,
            stderr_bytes: None,
            exit_code: None,
            signal: None,
        },
    }
}

fn captured_object(output: &CapturedOutput) -> Value {
    json!({ "stdout": output.stdout, "stderr": output.stderr, "truncated": output.truncated })
}

fn unavailable(message: impl Into<String>, output: &CapturedOutput) -> AnalysisError {
    let message = message.into();
    AnalysisError::capability_unavailable(PROVIDER, OPERATION, message.clone())
        .with_user_message(message)
        .with_captured_output(output.clone())
}

/// `validateCoreFileMappingAuthority`: confine NT_FILE mapping paths before GDB.
pub fn validate_mapping_authority(
    report: &Value,
    snapshot: &[u8],
    diagnostics: &CapturedOutput,
) -> Result<(), AnalysisError> {
    let notes = report.get("notes").and_then(Value::as_array);
    let Some(notes) = notes else { return Ok(()) };
    for note in notes {
        if note.get("type").and_then(Value::as_str) != Some("NT_FILE") {
            continue;
        }
        let index = note.get("index").cloned().unwrap_or(Value::Null);
        let refuse = |reason: &str| {
            let message = format!(
                "Core mapping note {index} cannot be confined to the owned debugger sysroot: {reason}."
            );
            let user =
                format!("{message} Omit include_debugger_context for basic recorded evidence.");
            AnalysisError::capability_unavailable(PROVIDER, OPERATION, message)
                .with_user_message(user)
                .with_captured_output(diagnostics.clone())
        };
        let offset = hex_to_u64(
            note.get("descriptor_location")
                .and_then(|l| l.get("offset")),
        );
        let length = hex_to_u64(note.get("descriptor_location").and_then(|l| l.get("bytes")));
        let (Some(offset), Some(length)) = (offset, length) else {
            return Err(refuse("missing mapping table header"));
        };
        let start = offset as usize;
        let end = start.saturating_add(length as usize);
        let bytes = snapshot.get(start..end.min(snapshot.len())).unwrap_or(&[]);
        if bytes.len() < 16 {
            return Err(refuse("missing mapping table header"));
        }
        let count = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
        let capacity = ((bytes.len() - 16) / 24) as u64;
        if count > capacity {
            return Err(refuse("mapping count exceeds its descriptor"));
        }
        let mut position = 16 + (count as usize) * 24;
        for _ in 0..count {
            let Some(end_index) = bytes[position..].iter().position(|&byte| byte == 0) else {
                return Err(refuse("unterminated mapping pathname"));
            };
            let path = &bytes[position..position + end_index];
            if path.first() != Some(&0x2f) {
                return Err(refuse("mapping pathname is not absolute"));
            }
            let mut component = 0;
            let len = path.len();
            for cursor in 0..=len {
                if cursor != len && path[cursor] != 0x2f {
                    continue;
                }
                let segment = &path[component..cursor];
                if segment == b"." || segment == b".." {
                    return Err(refuse("mapping pathname contains a dot segment"));
                }
                component = cursor + 1;
            }
            position += end_index + 1;
        }
        if bytes[position..].iter().any(|&byte| byte != 0) {
            return Err(refuse("mapping pathname coverage is unresolved"));
        }
    }
    Ok(())
}

/// `inspectPwndbgCore`: owned core-only debugger stage.
#[allow(clippy::too_many_arguments)]
pub fn inspect_core(
    environment: &HashMap<String, String>,
    architecture: &str,
    root_path: &str,
    diagnostics: &CapturedOutput,
    cancellation: &Cancellation,
    run_command: &dyn Fn(OwnedCommand, &str) -> Result<ProcessSnapshot, AnalysisError>,
) -> Result<Value, AnalysisError> {
    let gdb = environment
        .get("REA_PWNDBG_GDB")
        .cloned()
        .unwrap_or_else(|| "/usr/bin/gdb".to_owned());
    let entry = environment
        .get("REA_PWNDBG_GDBINIT")
        .cloned()
        .unwrap_or_default();
    let venv = environment
        .get("REA_PWNDBG_VENV_PATH")
        .cloned()
        .unwrap_or_default();
    let check_cancelled = || -> Result<(), AnalysisError> {
        if cancellation.reason().is_some() {
            Err(AnalysisError::cancelled(OPERATION).with_captured_output(diagnostics.clone()))
        } else {
            Ok(())
        }
    };
    check_cancelled()?;
    // Mode follows the configuration key, exactly like the TypeScript seam:
    // the GDB executable uses X_OK; the gdbinit file and venv directory use
    // R_OK alone. `node::access` only offers execute/read+execute, so the
    // read-only probe is done with a local `rustix::fs::access(READ_OK)`.
    for (key, path, kind, execute) in [
        ("REA_PWNDBG_GDB", gdb.as_str(), "file", true),
        ("REA_PWNDBG_GDBINIT", entry.as_str(), "file", false),
        ("REA_PWNDBG_VENV_PATH", venv.as_str(), "directory", false),
    ] {
        check_cancelled()?;
        if let Err(message) = probe_path(path, kind, execute) {
            return Err(unavailable(
                format!(
                    "{key} is unavailable at {path}: {message}. Configure the requested core-only context, or omit include_debugger_context for basic recorded evidence."
                ),
                diagnostics,
            ));
        }
    }
    check_cancelled()?;
    // Stage the owned debugger request within the same runtime root.
    let stage = node::join(root_path, "debugger");
    producer::make_private_directory(&stage).map_err(|error| adapter_fs(&error, diagnostics))?;
    let request_path = node::join(&stage, "request.json");
    let reply_path = node::join(&stage, "reply.json");
    let request = json!({
        "snapshot_path": node::join(root_path, "object.snapshot"),
        "reply_path": reply_path,
        "gdb": gdb,
        "architecture": architecture,
        "gdbinit": entry,
        "venv": venv,
    });
    producer::write_exclusive(&request_path, request.to_string().as_bytes(), 0o600)
        .map_err(|error| adapter_fs(&error, diagnostics))?;
    check_cancelled()?;
    let bridge = crate::pwntools::decoder::resolve_bridge("pwndbg", "launch.py")?;
    let executable = environment
        .get("REA_PWNTOOLS_PYTHON")
        .cloned()
        .unwrap_or_default();
    let cache = node::join(&stage, "cache");
    let config = node::join(&stage, "config");
    let command = OwnedCommand {
        command: executable.clone(),
        arguments: vec![
            "-I".to_owned(),
            bridge,
            node::join(&stage, "resource.failure"),
            request_path,
        ],
        cwd: stage.clone(),
        run_id: process_run_id(),
        overrides: vec![
            ("PWNDBG_NO_AUTOUPDATE".to_owned(), "1".to_owned()),
            ("PWNDBG_VENV_PATH".to_owned(), venv.clone()),
            ("PWNLIB_NOTERM".to_owned(), "1".to_owned()),
            ("TERM".to_owned(), "dumb".to_owned()),
            ("HOME".to_owned(), stage.clone()),
            ("XDG_CACHE_HOME".to_owned(), cache),
            ("XDG_CONFIG_HOME".to_owned(), config),
            ("PYTHONNOUSERSITE".to_owned(), "1".to_owned()),
            ("OPENBLAS_NUM_THREADS".to_owned(), "1".to_owned()),
            ("OMP_NUM_THREADS".to_owned(), "1".to_owned()),
        ],
    };
    check_cancelled()?;
    let snapshot = run_command(command, &gdb)?;
    let output = crate::pwntools::failures::captured(&snapshot);
    let combined = stage_output(diagnostics, Some(&output));
    let reply = read_reply(&reply_path, cancellation, diagnostics, &output)?;
    match reply {
        Reply::Ok(value) => {
            if value.get("status").and_then(Value::as_str) != Some("available") {
                return Err(AnalysisError::output(
                    OPERATION,
                    "Requested debugger context returned no core evidence.",
                )
                .with_captured_output(combined));
            }
            // `{ ...reply.value, diagnostics: output }` in schema key order.
            let mut debugger = value.as_object().cloned().unwrap_or_default();
            debugger.insert("diagnostics".into(), captured_object(&output));
            Ok(Value::Object(debugger))
        }
        Reply::Fail { reason, message } => match reason.as_str() {
            "unavailable" | "unsupported" => {
                Err(
                    AnalysisError::capability_unavailable(PROVIDER, OPERATION, message.clone())
                        .with_user_message(message)
                        .with_captured_output(combined),
                )
            }
            "format" | "output-limit" => {
                Err(AnalysisError::output(OPERATION, message).with_captured_output(combined))
            }
            _ => Err(crate::errors::provider_adapter(
                PROVIDER,
                OPERATION,
                Some(crate::errors::map([
                    ("stage", json!("debugger")),
                    ("reason", json!(message)),
                    ("captured_output", captured_object(&combined)),
                ])),
                None,
            )),
        },
    }
}

fn process_run_id() -> String {
    crate::process::run_id("rea-recorded-core-debugger-")
}

fn adapter_fs(error: &FsError, diagnostics: &CapturedOutput) -> AnalysisError {
    crate::errors::provider_adapter(
        PROVIDER,
        OPERATION,
        Some(crate::errors::map([
            ("stage", json!("debugger")),
            ("reason", json!(error.message)),
            (
                "captured_output",
                json!({
                    "stdout": diagnostics.stdout,
                    "stderr": diagnostics.stderr,
                    "truncated": diagnostics.truncated,
                }),
            ),
        ])),
        None,
    )
}

/// Local `fs.access(path, R_OK)` for the read-only gdbinit/venv probes. The
/// shared `node::access` only exposes execute and read+execute, so the exact
/// R_OK semantics are reproduced here with `rustix::fs::access(READ_OK)` and
/// Node's failure text through [`FsError::from_io`].
fn read_access(path: &str) -> Result<(), FsError> {
    #[cfg(unix)]
    {
        use rustix::fs::Access;
        rustix::fs::access(path, Access::READ_OK)
            .map_err(|errno| FsError::from_io(&std::io::Error::from(errno), "access", path))
    }
    #[cfg(not(unix))]
    {
        std::fs::metadata(path)
            .map(|_| ())
            .map_err(|error| FsError::from_io(&error, "access", path))
    }
}

/// `fs.stat(path)` directory test with Node's failure text.
fn stat_is_dir(path: &str) -> Result<bool, FsError> {
    std::fs::metadata(path)
        .map(|metadata| metadata.is_dir())
        .map_err(|error| FsError::from_io(&error, "stat", path))
}

fn probe_path(path: &str, kind: &str, execute: bool) -> Result<(), String> {
    if !node::is_absolute(path) {
        return Err("Expected an absolute caller-supplied path.".to_owned());
    }
    if execute {
        node::access(path, AccessMode::Execute).map_err(|error| error.message)?;
    } else {
        read_access(path).map_err(|error| error.message)?;
    }
    if kind == "file" {
        match node::stat_is_file(path) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Expected a file.".to_owned()),
            Err(error) => Err(error.message),
        }
    } else {
        match stat_is_dir(path) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Expected a directory.".to_owned()),
            Err(error) => Err(error.message),
        }
    }
}

enum Reply {
    Ok(Value),
    Fail { reason: String, message: String },
}

fn read_reply(
    reply_path: &str,
    cancellation: &Cancellation,
    diagnostics: &CapturedOutput,
    output: &CapturedOutput,
) -> Result<Reply, AnalysisError> {
    let combined = stage_output(diagnostics, Some(output));
    let snapshot =
        match artifact::read_stable(reply_path, release::OUTPUT_BYTES as usize, cancellation) {
            Ok(snapshot) => snapshot,
            Err(error) if error.reader_reason() == Some(ReaderReason::Cancelled) => {
                return Err(AnalysisError::cancelled(OPERATION).with_captured_output(combined));
            }
            Err(error) => {
                return Err(AnalysisError::output(
                    OPERATION,
                    format!("Core-only debugger reply failed: {}", error.message()),
                )
                .with_captured_output(combined));
            }
        };
    let text = std::str::from_utf8(&snapshot.bytes).map_err(|error| {
        AnalysisError::output(
            OPERATION,
            format!("Core-only debugger reply failed: {error}"),
        )
        .with_captured_output(combined.clone())
    })?;
    let value: Value = serde_json::from_str(text).map_err(|error| {
        AnalysisError::output(
            OPERATION,
            format!("Core-only debugger reply failed: {error}"),
        )
        .with_captured_output(combined.clone())
    })?;
    parse_reply(&value).ok_or_else(|| {
        AnalysisError::output(
            OPERATION,
            "Core-only debugger reply failed: invalid reply shape at root",
        )
        .with_captured_output(combined)
    })
}

fn parse_reply(value: &Value) -> Option<Reply> {
    let object = value.as_object()?;
    match object.get("ok")?.as_bool()? {
        true => Some(Reply::Ok(object.get("value")?.clone())),
        false => {
            let reason = object.get("reason")?.as_str()?;
            if !matches!(
                reason,
                "unavailable" | "unsupported" | "decoder" | "format" | "output-limit"
            ) {
                return None;
            }
            Some(Reply::Fail {
                reason: reason.to_owned(),
                message: object.get("message")?.as_str()?.to_owned(),
            })
        }
    }
}
