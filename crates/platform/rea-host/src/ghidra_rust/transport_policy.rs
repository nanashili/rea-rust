//! Request admission and reply-correlation policy for the Rust Ghidra worker.
//!
//! This module owns transport state, while process I/O, cancellation delivery,
//! and provider errors remain with the host.  Keeping those responsibilities
//! separate makes it possible to apply the same wire rules to synchronous and
//! asynchronous callers.

use std::time::{Duration, Instant};

use serde_json::Value;

use crate::ghidra_rust::protocol::{
    MAX_FRAME_BYTES, MAX_REQUEST_BYTES, WorkerFrame, WorkerRequest,
};

const MAX_REQUEST_OUTPUT_BYTES: usize = MAX_FRAME_BYTES * 4;
const MAX_SAFE_REQUEST_ID: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportPolicyError {
    WorkerFailed(String),
    Busy,
    RequestIdsExhausted,
    RequestTooLarge,
    OutputTooLarge,
    UnsolicitedFrame,
    ProgressAfterReply,
    InvalidProgressCounts,
    UncorrelatedReply { expected: u64, actual: u64 },
    CloseReplyMissing,
}

impl std::fmt::Display for TransportPolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WorkerFailed(message) => write!(formatter, "worker failed: {message}"),
            Self::Busy => formatter.write_str("transport already has an active request"),
            Self::RequestIdsExhausted => formatter.write_str("worker request IDs are exhausted"),
            Self::RequestTooLarge => formatter.write_str("worker request exceeds the size limit"),
            Self::OutputTooLarge => formatter.write_str("worker output exceeds the size limit"),
            Self::UnsolicitedFrame => formatter.write_str("worker sent an unsolicited frame"),
            Self::ProgressAfterReply => {
                formatter.write_str("worker sent progress after the response")
            }
            Self::InvalidProgressCounts => {
                formatter.write_str("worker progress counts are invalid")
            }
            Self::UncorrelatedReply { expected, actual } => write!(
                formatter,
                "worker reply ID {actual} does not match active request ID {expected}"
            ),
            Self::CloseReplyMissing => formatter.write_str("worker close reply was not received"),
        }
    }
}

impl std::error::Error for TransportPolicyError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Interruption {
    Timeout,
    Cancelled(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedRequest {
    pub request: WorkerRequest,
    pub deadline: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportEvent {
    Progress {
        sequence: usize,
        label: String,
        completed: usize,
        total: Option<usize>,
    },
    Reply {
        id: u64,
        result: Value,
    },
    Error {
        id: u64,
        code: i64,
        message: String,
        error_code: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveRequest {
    id: u64,
    method: String,
    bytes: usize,
    response_received: bool,
}

pub struct GhidraRustTransportPolicy {
    next_id: u64,
    sequence: usize,
    active: Option<ActiveRequest>,
    failure: Option<TransportPolicyError>,
    close_reply_received: bool,
}

impl Default for GhidraRustTransportPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl GhidraRustTransportPolicy {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            sequence: 0,
            active: None,
            failure: None,
            close_reply_received: false,
        }
    }

    pub fn is_busy(&self) -> bool {
        self.active.is_some()
    }

    pub fn failure(&self) -> Option<&TransportPolicyError> {
        self.failure.as_ref()
    }

    pub fn admit_request(
        &mut self,
        method: impl Into<String>,
        params: Value,
        timeout: Duration,
        now: Instant,
    ) -> Result<AdmittedRequest, TransportPolicyError> {
        self.require_usable()?;
        if self.is_busy() {
            return Err(TransportPolicyError::Busy);
        }
        if self.next_id > MAX_SAFE_REQUEST_ID {
            return Err(TransportPolicyError::RequestIdsExhausted);
        }

        let id = self.next_id;
        self.next_id += 1;
        let method = method.into();
        let request = WorkerRequest::new(id, method.clone(), params)
            .map_err(|error| self.protocol_failure(error))?;
        let frame_size = request
            .encode_line()
            .map_err(|error| self.protocol_failure(error))?
            .len();
        if frame_size > MAX_REQUEST_BYTES {
            return Err(
                self.protocol_failure("worker request exceeds the 64 KiB frame limit".into())
            );
        }

        self.active = Some(ActiveRequest {
            id,
            method,
            bytes: 0,
            response_received: false,
        });

        Ok(AdmittedRequest {
            request,
            deadline: now + timeout,
        })
    }

    pub fn admit_output(&mut self, bytes: usize) -> Result<(), TransportPolicyError> {
        self.require_usable()?;
        if self.active.is_none() {
            return Err(self.poison(TransportPolicyError::UnsolicitedFrame));
        }
        let exceeds_limit = {
            let active = self.active.as_mut().expect("active request was checked");
            active.bytes = active.bytes.saturating_add(bytes);
            active.bytes > MAX_REQUEST_OUTPUT_BYTES
        };
        if exceeds_limit {
            return Err(self.poison(TransportPolicyError::OutputTooLarge));
        }
        Ok(())
    }

    pub fn receive(&mut self, frame: WorkerFrame) -> Result<TransportEvent, TransportPolicyError> {
        self.require_usable()?;
        let Some(active) = self.active.as_ref().cloned() else {
            return Err(self.protocol_failure("uncorrelated worker frame".into()));
        };

        match frame {
            WorkerFrame::Progress {
                label,
                completed,
                total,
            } => {
                if active.response_received {
                    return Err(self.poison(TransportPolicyError::ProgressAfterReply));
                }
                if total.is_some_and(|total| completed > total) {
                    return Err(self.poison(TransportPolicyError::InvalidProgressCounts));
                }
                self.sequence += 1;
                Ok(TransportEvent::Progress {
                    sequence: self.sequence,
                    label,
                    completed,
                    total,
                })
            }
            WorkerFrame::Reply { id, result } => {
                self.validate_reply(&active, id)?;
                self.active
                    .as_mut()
                    .expect("active request was checked")
                    .response_received = true;
                if active.method == "close" {
                    self.close_reply_received = true;
                }
                Ok(TransportEvent::Reply { id, result })
            }
            WorkerFrame::Error {
                id,
                code,
                message,
                error_code,
            } => {
                self.validate_reply(&active, id)?;
                self.active
                    .as_mut()
                    .expect("active request was checked")
                    .response_received = true;

                // A worker-level error poisons the serial channel just as a
                // rejected pending operation does in the TypeScript
                // transport.  The error event is still returned so the
                // caller can retain its typed worker failure before closing
                // the owned request.
                self.fail(TransportPolicyError::WorkerFailed(message.clone()));

                Ok(TransportEvent::Error {
                    id,
                    code,
                    message,
                    error_code,
                })
            }
        }
    }

    pub fn interruption(
        &self,
        deadline: Instant,
        now: Instant,
        cancellation_reason: Option<&str>,
    ) -> Option<Interruption> {
        if now >= deadline {
            return Some(Interruption::Timeout);
        }
        cancellation_reason.map(|reason| Interruption::Cancelled(reason.to_owned()))
    }

    pub fn complete_request(&mut self, id: u64) -> Result<(), TransportPolicyError> {
        let Some(active) = self.active.as_ref().cloned() else {
            return Err(
                self.protocol_failure("request completion without an active request".into())
            );
        };
        if active.id != id || !active.response_received {
            return Err(self.protocol_failure("request completed before its reply".into()));
        }
        self.active = None;
        Ok(())
    }

    pub fn observe_close(&self) -> Result<(), TransportPolicyError> {
        if self.close_reply_received {
            Ok(())
        } else {
            Err(TransportPolicyError::CloseReplyMissing)
        }
    }

    pub fn fail(&mut self, error: TransportPolicyError) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
    }

    fn require_usable(&self) -> Result<(), TransportPolicyError> {
        self.failure.clone().map_or(Ok(()), Err)
    }

    fn protocol_failure(&mut self, message: String) -> TransportPolicyError {
        let error = TransportPolicyError::WorkerFailed(message);
        self.fail(error.clone());
        error
    }

    fn validate_reply(
        &mut self,
        active: &ActiveRequest,
        actual: u64,
    ) -> Result<(), TransportPolicyError> {
        if actual != active.id {
            return Err(self.poison(TransportPolicyError::UncorrelatedReply {
                expected: active.id,
                actual,
            }));
        }
        if active.response_received {
            return Err(self.poison(TransportPolicyError::ProgressAfterReply));
        }
        Ok(())
    }

    fn poison(&mut self, error: TransportPolicyError) -> TransportPolicyError {
        self.fail(error.clone());
        error
    }
}
