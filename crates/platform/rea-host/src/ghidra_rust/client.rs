//! Operation admission and lifecycle state for one Rust Ghidra client.
//!
//! The transport policy owns wire-level request IDs and reply correlation.
//! This module owns the client-facing rules around that transport: only
//! declared worker-backed operations may be admitted, one operation may own
//! the serial worker at a time, and closing is terminal.

use std::time::{Duration, Instant};

use serde_json::Value;

use crate::{
    ghidra_rust::operations::{GhidraRustOperation, OperationSelectionError},
    ghidra_rust::protocol::WorkerFrame,
    ghidra_rust::transport_policy::{
        AdmittedRequest, GhidraRustTransportPolicy, Interruption, TransportEvent,
        TransportPolicyError,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientPhase {
    Open,
    Closing,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientOperation {
    Public(GhidraRustOperation),
    Close,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientError {
    Closed,
    Closing,
    Busy,
    UnsupportedOperation(GhidraRustOperation),
    InvalidOperation(OperationSelectionError),
    Transport(TransportPolicyError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => formatter.write_str("Ghidra Rust client is closed"),
            Self::Closing => formatter.write_str("Ghidra Rust client is closing"),
            Self::Busy => formatter.write_str("Ghidra Rust client already has an active request"),
            Self::UnsupportedOperation(operation) => {
                write!(
                    formatter,
                    "operation is not backed by a worker command: {operation:?}"
                )
            }
            Self::InvalidOperation(error) => error.fmt(formatter),
            Self::Transport(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<TransportPolicyError> for ClientError {
    fn from(error: TransportPolicyError) -> Self {
        Self::Transport(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedClientRequest {
    pub operation: ClientOperation,
    pub request: AdmittedRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientEvent {
    Progress {
        operation: ClientOperation,
        sequence: usize,
        label: String,
        completed: usize,
        total: Option<usize>,
    },
    Reply {
        operation: ClientOperation,
        id: u64,
        result: Value,
    },
    Error {
        operation: ClientOperation,
        id: u64,
        code: i64,
        message: String,
        error_code: Option<String>,
    },
}

/// Coordinates declared operations with the serial worker transport.
pub struct GhidraRustClient {
    transport: GhidraRustTransportPolicy,
    phase: ClientPhase,
    active_operation: Option<ClientOperation>,
    active_request_id: Option<u64>,
}

impl Default for GhidraRustClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GhidraRustClient {
    pub fn new() -> Self {
        Self {
            transport: GhidraRustTransportPolicy::new(),
            phase: ClientPhase::Open,
            active_operation: None,
            active_request_id: None,
        }
    }

    pub fn phase(&self) -> ClientPhase {
        self.phase
    }

    pub fn is_busy(&self) -> bool {
        self.transport.is_busy()
    }

    pub fn failure(&self) -> Option<&TransportPolicyError> {
        self.transport.failure()
    }

    pub fn supports_operation(&self, operation: &str) -> bool {
        GhidraRustOperation::parse(operation)
            .map(|operation| operation == GhidraRustOperation::Health || operation.is_public())
            .unwrap_or(false)
    }

    /// Admit one worker-backed public operation and reserve the serial channel.
    pub fn admit(
        &mut self,
        operation: &str,
        params: Value,
        timeout: Duration,
        now: Instant,
    ) -> Result<AdmittedClientRequest, ClientError> {
        let operation =
            GhidraRustOperation::parse(operation).map_err(ClientError::InvalidOperation)?;
        self.require_open()?;
        if self.is_busy() {
            return Err(ClientError::Busy);
        }

        if !operation.is_public() || operation.worker_method().is_none() {
            return Err(ClientError::UnsupportedOperation(operation));
        }

        let method = operation
            .worker_method()
            .expect("worker-backed operation was checked");
        let request = self.transport.admit_request(method, params, timeout, now)?;
        self.active_operation = Some(ClientOperation::Public(operation));
        self.active_request_id = Some(request.request.id());

        Ok(AdmittedClientRequest {
            operation: ClientOperation::Public(operation),
            request,
        })
    }

    /// Begin terminal shutdown after all application work has settled.
    pub fn begin_close(
        &mut self,
        timeout: Duration,
        now: Instant,
    ) -> Result<AdmittedClientRequest, ClientError> {
        match self.phase {
            ClientPhase::Closed => return Err(ClientError::Closed),
            ClientPhase::Closing => return Err(ClientError::Closing),
            ClientPhase::Open => {}
        }
        if self.is_busy() {
            return Err(ClientError::Busy);
        }

        let request = self
            .transport
            .admit_request("close", serde_json::json!({}), timeout, now)?;
        self.phase = ClientPhase::Closing;
        self.active_operation = Some(ClientOperation::Close);
        self.active_request_id = Some(request.request.id());

        Ok(AdmittedClientRequest {
            operation: ClientOperation::Close,
            request,
        })
    }

    pub fn admit_output(&mut self, bytes: usize) -> Result<(), ClientError> {
        self.transport.admit_output(bytes).map_err(Into::into)
    }

    /// Report timeout or cancellation without consuming the active request.
    ///
    /// The host owns cancellation delivery and process cleanup.  Keeping this
    /// polling operation on the client preserves the transport deadline while
    /// allowing callers to terminate the worker and retain the active request
    /// until its response and cleanup have been settled.
    pub fn interruption(
        &self,
        request: &AdmittedClientRequest,
        now: Instant,
        cancellation_reason: Option<&str>,
    ) -> Option<Interruption> {
        if self.active_request_id != Some(request.request.request.id()) {
            return None;
        }

        self.transport
            .interruption(request.request.deadline, now, cancellation_reason)
    }

    pub fn receive(&mut self, frame: WorkerFrame) -> Result<ClientEvent, ClientError> {
        let operation = self.active_operation.ok_or(ClientError::Busy)?;
        let event = self.transport.receive(frame)?;
        Ok(match event {
            TransportEvent::Progress {
                sequence,
                label,
                completed,
                total,
            } => ClientEvent::Progress {
                operation,
                sequence,
                label,
                completed,
                total,
            },
            TransportEvent::Reply { id, result } => ClientEvent::Reply {
                operation,
                id,
                result,
            },
            TransportEvent::Error {
                id,
                code,
                message,
                error_code,
            } => ClientEvent::Error {
                operation,
                id,
                code,
                message,
                error_code,
            },
        })
    }

    pub fn complete(&mut self, id: u64) -> Result<(), ClientError> {
        self.transport.complete_request(id)?;
        self.active_operation = None;
        self.active_request_id = None;
        if self.phase == ClientPhase::Closing {
            self.transport.observe_close()?;
            self.phase = ClientPhase::Closed;
        }
        Ok(())
    }

    fn require_open(&self) -> Result<(), ClientError> {
        match self.phase {
            ClientPhase::Open => Ok(()),
            ClientPhase::Closing => Err(ClientError::Closing),
            ClientPhase::Closed => Err(ClientError::Closed),
        }
    }
}
