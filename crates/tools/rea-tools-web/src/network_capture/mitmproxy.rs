//! Linux mitmproxy capture adapter.
//!
//! The caller supplies the pinned `mitmdump` executable.  REA owns only the
//! private request, snapshot and reply files and the child process lifecycle;
//! it never starts a proxy listener or replays recorded destinations.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rea_core::analysis_error::AnalysisError;
use rea_core::analysis_error::cleanup::with_cleanup_failure;
use rea_core::cancellation::Cancellation;
use rea_host::fs::stable_file;
use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess};
use rea_host::process::windows::job::WindowsJobLimits;
use rea_mcp::{Session, SessionResource};
use serde_json::{Value, json};

use super::errors::{self, CaptureFormatError};
use super::limits::{CAPTURE_INPUT_BYTES, CAPTURE_OUTPUT_BYTES};
use super::redaction;

const OPERATION: &str = "inspect_web_network_capture";
const PROVIDER_ID: &str = "mitmproxy-native-tnetstring";
const PROVIDER_NAME: &str = "REA offline native mitmproxy adapter";
const PROVIDER_VERSION: &str = "12.2.3";
const TIMEOUT: Duration = Duration::from_secs(30);
const DIAGNOSTIC_BYTES: usize = 1024 * 1024;
const MITMPROXY_MEMORY_BYTES: u64 = 768 * 1024 * 1024;
const EMBEDDED_BRIDGE: &[u8] = include_bytes!("../../../../../../bridge/mitmproxy/capture.py");

#[cfg(unix)]
type HostFiles = rea_host::fs::unix_file::UnixFiles;
#[cfg(windows)]
type HostFiles = rea_host::fs::windows_file::WindowsFiles;

/// Run the checked-in mitmproxy bridge and return its complete producer value.
pub(super) fn decode(
    input: &Value,
    sensitive_values: &[String],
    configured_command: Option<&str>,
    cancellation: &Cancellation,
    session: &Arc<Session>,
) -> Result<Value, AnalysisError> {
    let command = resolve_command(configured_command)?;
    let capture_path = input
        .get("capture_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let snapshot = read_capture(capture_path, cancellation, session)?;

    let runtime = tempfile::Builder::new()
        .prefix("rea-mitmproxy-")
        .tempdir()
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
    // Keep the temporary directory owned by `TempDir` until identity capture
    // succeeds.  If identity admission fails, its destructor still removes
    // the directory instead of leaking an unowned path.
    let cleanup_owner = Arc::new(MitmproxyCleanup::new(runtime.path().to_owned())?);
    let runtime_path = runtime.keep();
    let result = decode_runtime(
        &command,
        capture_path,
        snapshot,
        sensitive_values,
        &runtime_path,
        cleanup_owner.as_ref(),
        cancellation,
        session,
    );
    finish_with_cleanup(result, cleanup_owner, session)
}

fn decode_runtime(
    command: &str,
    capture_path: &str,
    snapshot: stable_file::Snapshot,
    sensitive_values: &[String],
    runtime_path: &Path,
    cleanup_owner: &MitmproxyCleanup,
    cancellation: &Cancellation,
    session: &Arc<Session>,
) -> Result<Value, AnalysisError> {
    let (reply_path, spec) =
        prepare_runtime(command, runtime_path, &snapshot.bytes, sensitive_values)?;
    let mut child = OwnedChildProcess::launch(spec).map_err(|error| {
        AnalysisError::provider_adapter("mitmproxy", OPERATION)
            .with_user_message(format!("Unable to launch configured mitmdump: {error}"))
    })?;
    let wait = wait_for_completion(&mut child, cancellation);
    cleanup_owner.attach_child(child);
    wait?;

    let reply_bytes = read_reply(&reply_path, cancellation, session)?;
    let reply: Value = serde_json::from_slice(&reply_bytes)
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
    let mut result = successful_reply(reply)?;
    let path = redaction::redact_explicit_text(capture_path, sensitive_values);
    result["format"] = Value::String("mitmproxy".to_owned());
    result["artifact"] = json!({
        "path": path,
        "sha256": snapshot.sha256,
        "bytes": snapshot.bytes.len(),
    });
    result["runtime_attribution"] = Value::String("unknown".to_owned());
    Ok(result)
}

fn prepare_runtime(
    command: &str,
    runtime_path: &Path,
    bytes: &[u8],
    sensitive_values: &[String],
) -> Result<(PathBuf, ChildLaunchSpec), AnalysisError> {
    let snapshot_path = runtime_path.join("capture.snapshot");
    let request_path = runtime_path.join("request.json");
    let reply_path = runtime_path.join("reply.json");
    std::fs::write(&snapshot_path, bytes)
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
    let request = json!({
        "snapshot_path": snapshot_path,
        "reply_path": reply_path,
        "sensitive_values": sensitive_values,
    });
    std::fs::write(
        &request_path,
        serde_json::to_vec(&request)
            .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?,
    )
    .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;

    let bridge = runtime_path.join("capture.py");
    std::fs::write(&bridge, EMBEDDED_BRIDGE)
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
    let spec = ChildLaunchSpec {
        executable: PathBuf::from(command),
        arguments: ChildLaunchSpec::arguments([
            OsString::from("--no-server"),
            OsString::from("-q"),
            OsString::from("--set"),
            OsString::from(format!("confdir={}", runtime_path.display())),
            OsString::from("--set"),
            OsString::from(format!("rea_request_path={}", request_path.display())),
            OsString::from("-s"),
            bridge.as_os_str().to_owned(),
        ]),
        working_directory: Some(runtime_path.to_owned()),
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: Some(MITMPROXY_MEMORY_BYTES),
            cpu_seconds: None,
        },
    };
    Ok((reply_path, spec))
}

/// Complete cleanup after the producer result is known. The owner remains in
/// the session whenever either child settlement or runtime removal is still
/// uncertain, so a later session close can retry both independently.
fn finish_with_cleanup(
    result: Result<Value, AnalysisError>,
    owner: Arc<MitmproxyCleanup>,
    session: &Arc<Session>,
) -> Result<Value, AnalysisError> {
    match owner.close() {
        Ok(()) => result,
        Err(cleanup) => {
            session.own(owner);
            match result {
                Ok(_) => Err(cleanup),
                Err(primary) => Err(with_cleanup_failure(primary, cleanup, OPERATION)),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl DirectoryIdentity {
    fn capture(path: &Path) -> Result<Self, AnalysisError> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AnalysisError::output(
                OPERATION,
                "mitmproxy runtime root was not an owned directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(AnalysisError::output(
                OPERATION,
                "mitmproxy runtime identity is unavailable on this host",
            ))
        }
    }

    fn still_owned(self, path: &Path) -> Result<Option<bool>, std::io::Error> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Some(
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.dev() == self.device
                    && metadata.ino() == self.inode,
            ))
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Ok(Some(false))
        }
    }
}

struct MitmproxyCleanup {
    runtime_path: PathBuf,
    identity: DirectoryIdentity,
    child: Mutex<Option<OwnedChildProcess>>,
}

impl MitmproxyCleanup {
    fn new(runtime_path: PathBuf) -> Result<Self, AnalysisError> {
        Ok(Self {
            identity: DirectoryIdentity::capture(&runtime_path)?,
            runtime_path,
            child: Mutex::new(None),
        })
    }

    fn attach_child(&self, child: OwnedChildProcess) {
        *self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(child);
    }

    fn close_child(&self, resources: &mut Vec<String>, reasons: &mut Vec<String>) {
        let mut child = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(mut owned) = child.take() else {
            return;
        };
        match owned.retry_cleanup(124) {
            Ok(()) => {}
            Err(error) => {
                reasons.push(error.to_string());
                resources.push("mitmproxy child process".to_owned());
                *child = Some(owned);
            }
        }
    }

    fn close_runtime(&self, resources: &mut Vec<String>, reasons: &mut Vec<String>) {
        match self.identity.still_owned(&self.runtime_path) {
            Ok(None) => return,
            Ok(Some(true)) => match std::fs::remove_dir_all(&self.runtime_path) {
                Ok(()) => {}
                Err(error) => {
                    reasons.push(error.to_string());
                    resources.push(self.runtime_path.display().to_string());
                }
            },
            Ok(Some(false)) => {
                reasons.push("mitmproxy runtime path is no longer the owned directory".to_owned());
                resources.push(self.runtime_path.display().to_string());
            }
            Err(error) => {
                reasons.push(format!(
                    "Unable to verify mitmproxy runtime ownership: {error}"
                ));
                resources.push(self.runtime_path.display().to_string());
            }
        }
    }
}

impl SessionResource for MitmproxyCleanup {
    fn close(&self) -> Result<(), AnalysisError> {
        let mut resources = Vec::new();
        let mut reasons = Vec::new();
        self.close_child(&mut resources, &mut reasons);
        if resources
            .iter()
            .any(|resource| resource == "mitmproxy child process")
        {
            reasons.push("mitmproxy runtime remains until child ownership is released".to_owned());
            resources.push(self.runtime_path.display().to_string());
        } else {
            self.close_runtime(&mut resources, &mut reasons);
        }
        if reasons.is_empty() {
            Ok(())
        } else {
            let reason = reasons.join("; ");
            Err(AnalysisError::output(OPERATION, reason.clone()).with_cleanup(reason, resources))
        }
    }
}

fn read_capture(
    path: &str,
    cancellation: &Cancellation,
    session: &Arc<Session>,
) -> Result<stable_file::Snapshot, AnalysisError> {
    stable_file::read(
        Arc::new(HostFiles {}),
        Path::new(path),
        CAPTURE_INPUT_BYTES,
        cancellation,
    )
    .map_err(|mut failure| {
        let mut error = AnalysisError::provider_adapter("mitmproxy", OPERATION).with_user_message(
            format!("Unable to read a stable retained capture: {failure:?}"),
        );
        if let Some(lease) = failure.retained.take() {
            let owner = Arc::new(StableCaptureCleanup {
                resource: path.to_owned(),
                lease: Mutex::new(Some(lease)),
            });
            session.own(owner);
            error = error.with_cleanup(
                "The retained capture handle remains owned for session cleanup.",
                vec![path.to_owned()],
            );
        }
        error
    })
}

struct StableCaptureCleanup {
    resource: String,
    lease: Mutex<Option<stable_file::Lease<HostFiles>>>,
}

impl SessionResource for StableCaptureCleanup {
    fn close(&self) -> Result<(), AnalysisError> {
        let mut lease = self
            .lease
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(owner) = lease.as_mut() else {
            return Ok(());
        };
        match owner.close() {
            Ok(()) => {
                *lease = None;
                Ok(())
            }
            Err(failure) => Err(AnalysisError::output(OPERATION, failure.error.to_string())
                .with_cleanup(failure.error.to_string(), vec![self.resource.clone()])),
        }
    }
}

fn read_reply(
    path: &Path,
    cancellation: &Cancellation,
    session: &Arc<Session>,
) -> Result<Vec<u8>, AnalysisError> {
    if std::fs::metadata(path)
        .map(|metadata| metadata.len() > CAPTURE_OUTPUT_BYTES as u64)
        .unwrap_or(false)
    {
        return Err(errors::from_capture_error(
            "mitmproxy",
            CaptureFormatError::new(
                "resource-limit",
                "Native reply exceeds the complete-evidence output budget.",
                "",
            ),
        ));
    }
    stable_file::read(
        Arc::new(HostFiles {}),
        path,
        CAPTURE_OUTPUT_BYTES,
        cancellation,
    )
    .map(|snapshot| snapshot.bytes)
    .map_err(|mut failure| {
        let mut error = AnalysisError::output(
            OPERATION,
            format!("Owned mitmproxy decoder reply was not readable: {failure:?}"),
        );
        if let Some(lease) = failure.retained.take() {
            session.own(Arc::new(StableCaptureCleanup {
                resource: path.display().to_string(),
                lease: Mutex::new(Some(lease)),
            }));
            error = error.with_cleanup(
                "The retained decoder reply handle remains owned for session cleanup.",
                vec![path.display().to_string()],
            );
        }
        error
    })
}

fn resolve_command(configured: Option<&str>) -> Result<String, AnalysisError> {
    if std::env::consts::OS != "linux" {
        return Err(errors::mitmproxy_unavailable());
    }
    let configured = configured.filter(|path| Path::new(path).is_absolute());
    let Some(configured) = configured else {
        return Err(errors::mitmproxy_unavailable());
    };
    let metadata = std::fs::metadata(configured).map_err(|_| unavailable(configured))?;
    if !metadata.is_file() || !is_executable(&metadata) {
        return Err(unavailable(configured));
    }
    Ok(configured.to_owned())
}

fn unavailable(command: &str) -> AnalysisError {
    let reason = format!("Configured mitmdump executable is unavailable: {command}.");
    AnalysisError::capability_unavailable("mitmproxy", OPERATION, reason.clone())
        .with_user_message(reason)
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode();
    mode & 0o500 == 0o500
}

#[cfg(not(unix))]
fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    true
}

fn wait_for_completion(
    child: &mut OwnedChildProcess,
    cancellation: &Cancellation,
) -> Result<(), AnalysisError> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let output = child
            .read_output()
            .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
        if output.exceeds_limit(DIAGNOSTIC_BYTES) {
            let _ = child.cancel(1);
            return Err(AnalysisError::output(
                OPERATION,
                "mitmdump diagnostic output exceeds 1 MiB.",
            ));
        }
        if let Some(exit) = child
            .try_wait()
            .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?
        {
            let output = child
                .drain_output()
                .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
            if output.exceeds_limit(DIAGNOSTIC_BYTES) {
                return Err(AnalysisError::output(
                    OPERATION,
                    "mitmdump diagnostic output exceeds 1 MiB.",
                ));
            }
            if exit.code != 0 {
                return Err(AnalysisError::provider_adapter("mitmproxy", OPERATION)
                    .with_user_message(format!(
                        "Configured mitmdump exited with status {}.",
                        exit.code
                    )));
            }
            return Ok(());
        }
        if cancellation.reason().is_some() {
            let _ = child.cancel(130);
            return Err(AnalysisError::cancelled(OPERATION));
        }
        if Instant::now() >= deadline {
            let _ = child.cancel(124);
            return Err(AnalysisError::timeout(OPERATION, 30_000));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn successful_reply(reply: Value) -> Result<Value, AnalysisError> {
    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        let value = reply
            .get("value")
            .cloned()
            .ok_or_else(|| AnalysisError::output(OPERATION, "Decoder reply omitted value."));
        let value = value?;
        let decoder = value.get("decoder");
        if decoder
            .and_then(|item| item.get("id"))
            .and_then(Value::as_str)
            != Some(PROVIDER_ID)
            || decoder
                .and_then(|item| item.get("name"))
                .and_then(Value::as_str)
                != Some(PROVIDER_NAME)
            || decoder
                .and_then(|item| item.get("version"))
                .and_then(Value::as_str)
                != Some(PROVIDER_VERSION)
        {
            return Err(errors::from_capture_error(
                "mitmproxy",
                CaptureFormatError::new(
                    "unsupported",
                    "Capture decoder changed the selected upstream profile identity.",
                    "",
                ),
            ));
        }
        return Ok(value);
    }
    let reason: &'static str = match reply
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("decoder")
    {
        "format" => "format",
        "unsupported" => "unsupported",
        "input-limit" => "input-limit",
        "expanded-limit" => "expanded-limit",
        "resource-limit" => "resource-limit",
        "limit" => "limit",
        _ => "decoder",
    };
    let message = reply
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("Offline native decoder failed.");
    let pointer = reply.get("pointer").and_then(Value::as_str).unwrap_or("");
    Err(errors::from_capture_error(
        "mitmproxy",
        CaptureFormatError::new(reason, message.to_owned(), pointer.to_owned()),
    ))
}
