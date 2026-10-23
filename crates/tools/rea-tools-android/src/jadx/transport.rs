//! Newline-delimited JSON-RPC MCP client over an owned protocol child.
//!
//! Compatibility owner: `src/android/JadxMcpTransport.ts` and the SDK 2.3.1
//! "legacy" connect reproduced by `JadxSession.ts`. Frames are bounded at
//! 8 MiB per line; one operation may produce at most 32 MiB of stdout+stderr
//! since `begin_operation`. UTF-8 decoding is fatal.

use crate::common::process::{CommandSpec, LAUNCHER_STREAM_CAPTURE_BYTES, ProtocolChild};
use rea_core::analysis_error::CapturedOutput;
use rea_core::cancellation::Cancellation;
use rea_host::process::launcher::ProcessLaunchError;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_OPERATION_BYTES: u64 = 32 * 1024 * 1024;

/// Accepted negotiated protocol versions (newest first).
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 5] = [
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2024-10-07",
];
/// The protocol version REA advertises in `initialize`.
pub const INITIALIZE_PROTOCOL_VERSION: &str = "2025-11-25";

/// The first observed failure, recorded before cleanup.
#[derive(Clone, Debug)]
pub enum TransportFailure {
    Process { message: String },
    Exit,
    Protocol { message: String },
    Interrupted { reason: String },
}

/// Why a transport call did not complete.
#[derive(Debug)]
pub enum TransportError {
    /// A JSON-RPC error reply (`MCP error <code>: <message>`).
    Rpc { code: i64, message: String },
    /// A protocol/framing/decoding violation.
    Protocol(String),
    /// The operation output bound was exceeded.
    OperationLimit,
    /// The child exited or produced no further output.
    Closed(String),
    /// The caller cancelled.
    Cancelled(String),
    /// The operation deadline elapsed.
    Timeout,
    /// A launcher failure.
    Launch(String),
}

/// SDK-framed stdio with REA-owned process cleanup.
pub struct JadxTransport {
    spec: CommandSpec,
    pub run_id: String,
    child: Option<ProtocolChild>,
    frame: Vec<u8>,
    bytes: u64,
    pending: Vec<Value>,
    failure: Option<TransportFailure>,
    started: bool,
}

impl JadxTransport {
    pub fn new(spec: CommandSpec, run_id: String) -> Self {
        Self {
            spec,
            run_id,
            child: None,
            frame: Vec::new(),
            bytes: 0,
            pending: Vec::new(),
            failure: None,
            started: false,
        }
    }

    /// The command used to launch the protocol child (for startup diagnostics).
    pub fn command(&self) -> String {
        self.spec.program.display().to_string()
    }

    /// Record the first observed failure.
    fn record(&mut self, failure: TransportFailure) {
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
    }

    /// The first observed failure, if any.
    pub fn observed_failure(&self) -> Option<&TransportFailure> {
        self.failure.as_ref()
    }

    /// Acquire the owned protocol child (once).
    pub fn start(&mut self) -> Result<(), TransportError> {
        if self.started {
            return Err(TransportError::Protocol(
                "JADX transport cannot be restarted".into(),
            ));
        }
        self.started = true;
        match ProtocolChild::launch(&self.spec, LAUNCHER_STREAM_CAPTURE_BYTES) {
            Ok(child) => {
                self.child = Some(child);
                Ok(())
            }
            Err(error) => {
                self.record(TransportFailure::Process {
                    message: error.message.clone(),
                });
                Err(TransportError::Launch(error.message))
            }
        }
    }

    /// Retire the engine before an operation if lifetime stdout exceeds 4 MiB
    /// (the launcher's per-stream capture bound is 8 MiB).
    pub fn should_retire_for_capture(&self) -> bool {
        self.child
            .as_ref()
            .map(|child| child.lifetime_bytes().0 > (LAUNCHER_STREAM_CAPTURE_BYTES / 2) as u64)
            .unwrap_or(false)
    }

    /// Whether protocol (stdout) bytes were dropped by the launcher.
    pub fn stdout_capture_truncated(&self) -> bool {
        self.child
            .as_ref()
            .map(ProtocolChild::stdout_capture_truncated)
            .unwrap_or(false)
    }

    /// Scope the byte budget and diagnostics to the next serialized request.
    pub fn begin_operation(&mut self) {
        self.bytes = 0;
        if let Some(child) = self.child.as_mut() {
            child.reset_diagnostics();
        }
    }

    /// Write one serialized JSON-RPC message followed by a newline.
    fn send(&mut self, message: &Value) -> Result<(), TransportError> {
        let child = self.child.as_ref().ok_or_else(|| {
            TransportError::Protocol("JADX protocol process is not writable".into())
        })?;
        let mut line = serde_json::to_vec(message).map_err(|error| {
            TransportError::Protocol(format!("could not serialize message: {error}"))
        })?;
        line.push(b'\n');
        child.write_all(&line).map_err(|error| {
            self.failure.get_or_insert(TransportFailure::Process {
                message: error.message.clone(),
            });
            TransportError::Launch(error.message)
        })
    }

    /// Poll the child, framing complete JSON-RPC messages into `pending`.
    fn pump(&mut self) -> Result<(), TransportError> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| TransportError::Closed("protocol child stopped".into()))?;
        let increment = child.poll().map_err(|error: ProcessLaunchError| {
            self.failure.get_or_insert(TransportFailure::Process {
                message: error.message.clone(),
            });
            TransportError::Launch(error.message)
        })?;
        self.bytes += increment.stdout.len() as u64 + increment.stderr.len() as u64;
        if self.bytes > MAX_OPERATION_BYTES {
            let message = format!(
                "JADX operation output exceeds {MAX_OPERATION_BYTES} bytes; no complete result is available"
            );
            self.record(TransportFailure::Protocol {
                message: message.clone(),
            });
            return Err(TransportError::OperationLimit);
        }
        if increment.stdout_truncated {
            // Protocol bytes were dropped by the launcher: treat as the same
            // operation-bound violation as the TS transport.
            let message = format!(
                "JADX operation output exceeds {MAX_OPERATION_BYTES} bytes; no complete result is available"
            );
            self.record(TransportFailure::Protocol {
                message: message.clone(),
            });
            return Err(TransportError::OperationLimit);
        }
        let mut offset = 0;
        let stdout = &increment.stdout;
        while offset < stdout.len() {
            let newline = stdout[offset..].iter().position(|byte| *byte == b'\n');
            let end = newline.map_or(stdout.len(), |index| offset + index);
            let fragment = &stdout[offset..end];
            if self.frame.len() + fragment.len() > MAX_FRAME_BYTES {
                let message = format!("JADX MCP frame exceeds {MAX_FRAME_BYTES} bytes");
                self.record(TransportFailure::Protocol {
                    message: message.clone(),
                });
                return Err(TransportError::Protocol(message));
            }
            self.frame.extend_from_slice(fragment);
            match newline {
                None => return Ok(()),
                Some(index) => {
                    let line = std::mem::take(&mut self.frame);
                    let text = String::from_utf8(line).map_err(|_| {
                        let message = "JADX MCP frame is not valid UTF-8".to_owned();
                        self.record(TransportFailure::Protocol {
                            message: message.clone(),
                        });
                        TransportError::Protocol(message)
                    })?;
                    let value: Value = serde_json::from_str(&text).map_err(|error| {
                        let message = format!("JADX MCP frame is not valid JSON-RPC: {error}");
                        self.record(TransportFailure::Protocol {
                            message: message.clone(),
                        });
                        TransportError::Protocol(message)
                    })?;
                    self.pending.push(value);
                    offset = index + 1;
                }
            }
        }
        Ok(())
    }

    /// Await one JSON-RPC response for `id`, answering server requests
    /// (ping → {}, others → -32601) and ignoring notifications.
    fn await_response(
        &mut self,
        id: u64,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> Result<Value, TransportError> {
        loop {
            // Dispatch any buffered messages first.
            while !self.pending.is_empty() {
                let message = self.pending.remove(0);
                if let Some(result) = self.dispatch(id, message)? {
                    return Ok(result);
                }
            }
            if let Some(reason) = cancellation.reason() {
                return Err(TransportError::Cancelled(reason.to_owned()));
            }
            if Instant::now() >= deadline {
                return Err(TransportError::Timeout);
            }
            self.pump()?;
            if self.pending.is_empty() {
                if let Some(child) = self.child.as_ref()
                    && child.exit_code().is_some()
                    && child.output_closed()
                {
                    self.record(TransportFailure::Exit);
                    return Err(TransportError::Closed("protocol child exited".into()));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    /// Classify one received message. Returns the result for `id` when matched.
    fn dispatch(&mut self, id: u64, message: Value) -> Result<Option<Value>, TransportError> {
        let object = match message.as_object() {
            Some(object) => object,
            None => return Ok(None),
        };
        let message_id = object.get("id");
        let has_method = object.get("method").and_then(Value::as_str).is_some();
        if has_method {
            // A request or notification from the server.
            if let Some(request_id) = message_id.filter(|value| !value.is_null()) {
                let method = object
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let reply = if method == "ping" {
                    json!({ "jsonrpc": "2.0", "id": request_id, "result": {} })
                } else {
                    json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": { "code": -32601, "message": "Method not found" },
                    })
                };
                self.send(&reply)?;
            }
            // Notifications are ignored.
            return Ok(None);
        }
        // A response.
        if message_id.and_then(Value::as_u64) != Some(id) {
            // Out-of-order responses to other ids are not expected (one in
            // flight at a time), but ignore anything that is not ours.
            return Ok(None);
        }
        if let Some(error) = object.get("error").and_then(Value::as_object) {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            let text = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            return Err(TransportError::Rpc {
                code,
                message: text,
            });
        }
        Ok(Some(object.get("result").cloned().unwrap_or(Value::Null)))
    }

    /// Send a request and await its response, bounded by `timeout_ms`.
    pub fn request(
        &mut self,
        id: u64,
        method: &str,
        params: Value,
        timeout_ms: u64,
        cancellation: &Cancellation,
    ) -> Result<Value, TransportError> {
        let message = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        self.send(&message)?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        self.await_response(id, deadline, cancellation)
    }

    /// Send a notification (no id, no response).
    pub fn notify(&mut self, method: &str, params: Value) -> Result<(), TransportError> {
        let message = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.send(&message)
    }

    /// Record an interruption reason distinct from teardown errors.
    pub fn interrupt(&mut self, reason: &str) {
        self.record(TransportFailure::Interrupted {
            reason: reason.to_owned(),
        });
    }

    /// Captured provider stderr diagnostics.
    pub fn diagnostics(&self) -> Option<CapturedOutput> {
        let child = self.child.as_ref()?;
        let (stderr, stderr_bytes, truncated) = child.diagnostics();
        Some(CapturedOutput {
            stdout: String::new(),
            stderr,
            truncated: truncated || !child.output_closed(),
            stdout_bytes: None,
            stderr_bytes: Some(stderr_bytes),
            exit_code: child.exit_code().map(|code| Some(i64::from(code))),
            signal: None,
        })
    }

    /// Stop the owned child and prove its process group/job settled.
    /// A failed stop keeps the child; a later call retries it.
    pub fn close(&mut self) -> Result<(), ProcessLaunchError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        child.close_input();
        child.stop()?;
        self.child = None;
        Ok(())
    }

    /// Whether the owned child has been proven stopped.
    pub fn is_stopped(&self) -> bool {
        self.child
            .as_ref()
            .map(ProtocolChild::is_stopped)
            .unwrap_or(true)
    }
}
