//! Validation and projection for individual Rust-Ghidra batch results.
//!
//! The worker reports the selector it received together with optional canonical
//! procedure facts.  This module keeps those two identities separate and turns
//! missing pseudocode into a typed, transport-oriented item failure.  Runtime
//! adapters can then attach their application-specific error algebra without
//! reinterpreting the worker payload.

use serde_json::{Value, json};

pub const MAX_PSEUDOCODE_BYTES: usize = 512 * 1024;
pub const MAX_SELECTOR_BYTES: usize = 18;
pub const MAX_ADDRESS_BYTES: usize = 18;
pub const MAX_ERROR_CODE_BYTES: usize = 64;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 4 * 1024;
const BATCH_OPERATION: &str = "batch_decompile";
const TIMEOUT_REMEDIATION: &str = "Increase REA_GHIDRA_RUST_TIMEOUT_MS or select a smaller batch.";
const TRANSPORT_REMEDIATION: &str = "Discover retained records with get_evidence_bundle and detail: summary, then inspect compatible records through inspect_analysis_view using an exact Evidence reference. Export complete retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. The connection remains usable.";
const OUTPUT_REMEDIATION: &str = "Analysis returned an unreadable result. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerBatchItem {
    pub selector: String,
    pub address: Option<String>,
    pub name: Option<String>,
    pub pseudocode: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProcedure {
    pub address: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcedureIdentity {
    Resolved(ResolvedProcedure),
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchItemStatus {
    Succeeded { pseudocode: String },
    Failed { error: BatchItemError },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchItemProjection {
    pub address: String,
    pub procedure: ProcedureIdentity,
    pub status: BatchItemStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchItemErrorKind {
    Deadline,
    PseudocodeLimit,
    BatchOutputLimit,
    Output,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchItemError {
    pub kind: BatchItemErrorKind,
    pub message: String,
    pub worker_error_code: Option<String>,
    pub timeout_ms: u64,
}

impl WorkerBatchItem {
    pub fn validate(&self) -> Result<(), String> {
        validate_bounded(&self.selector, MAX_SELECTOR_BYTES, "worker batch selector")?;
        validate_optional_bounded(&self.pseudocode, MAX_PSEUDOCODE_BYTES, "worker pseudocode")?;
        validate_optional_bounded(&self.error_code, MAX_ERROR_CODE_BYTES, "worker error code")?;
        validate_optional_bounded(
            &self.error_message,
            MAX_ERROR_MESSAGE_BYTES,
            "worker error message",
        )?;

        if let Some(address) = self.address.as_deref() {
            require_nonempty_bounded(address, MAX_ADDRESS_BYTES, "worker procedure address")?;
        }
        if let Some(name) = self.name.as_deref() {
            validate_bounded(name, 4 * 1024, "worker procedure name")?;
        }

        Ok(())
    }

    /// Preserve a resolved procedure only when both canonical fields exist.
    pub fn procedure_identity(&self) -> ProcedureIdentity {
        match (&self.address, &self.name) {
            (Some(address), Some(name)) => ProcedureIdentity::Resolved(ResolvedProcedure {
                address: address.clone(),
                name: name.clone(),
            }),
            _ => ProcedureIdentity::Unknown,
        }
    }

    pub fn project(&self, timeout_ms: u64) -> Result<BatchItemProjection, String> {
        self.validate()?;
        let procedure = self.procedure_identity();

        if let Some(pseudocode) = &self.pseudocode {
            if pseudocode.trim().is_empty() {
                return Err("a successful batch item must include pseudocode".to_owned());
            }

            if !matches!(procedure, ProcedureIdentity::Resolved(_)) {
                return Ok(self.failed_projection(procedure, timeout_ms));
            }

            if self.error_code.is_some() || self.error_message.is_some() {
                return Err(
                    "a successful batch item must not include worker error fields".to_owned(),
                );
            }

            return Ok(BatchItemProjection {
                address: self.selector.clone(),
                procedure,
                status: BatchItemStatus::Succeeded {
                    pseudocode: pseudocode.clone(),
                },
            });
        }

        if self
            .error_message
            .as_deref()
            .is_none_or(|message| message.trim().is_empty())
        {
            return Err("a failed batch item must include an error message".to_owned());
        }

        Ok(self.failed_projection(procedure, timeout_ms))
    }

    fn failed_projection(
        &self,
        procedure: ProcedureIdentity,
        timeout_ms: u64,
    ) -> BatchItemProjection {
        BatchItemProjection {
            address: self.selector.clone(),
            procedure,
            status: BatchItemStatus::Failed {
                error: self.error(timeout_ms),
            },
        }
    }

    pub fn error(&self, timeout_ms: u64) -> BatchItemError {
        let message = self
            .error_message
            .clone()
            .unwrap_or_else(|| "The worker returned no pseudocode.".to_owned());
        let kind = match self.error_code.as_deref() {
            Some("REQUEST_DEADLINE") => BatchItemErrorKind::Deadline,
            Some("OUTPUT_LIMIT") => BatchItemErrorKind::PseudocodeLimit,
            Some("BATCH_OUTPUT_LIMIT") => BatchItemErrorKind::BatchOutputLimit,
            _ => BatchItemErrorKind::Output,
        };

        BatchItemError {
            kind,
            message,
            worker_error_code: self.error_code.clone(),
            timeout_ms,
        }
    }
}

impl BatchItemProjection {
    /// Project one item while retaining the accumulator's caller-input index.
    ///
    /// Durability is a batch-level receipt and remains owned by the batch
    /// accumulator; callers should attach it alongside this item projection.
    pub fn to_json_with_input_index(&self, input_index: usize) -> Value {
        let mut projection = self.to_json();
        if let Some(object) = projection.as_object_mut() {
            object.insert("input_index".to_owned(), json!(input_index));
        }
        projection
    }

    pub fn to_json(&self) -> Value {
        let procedure = match &self.procedure {
            ProcedureIdentity::Resolved(procedure) => json!({
                "status": "resolved",
                "address": procedure.address,
                "name": procedure.name,
            }),
            ProcedureIdentity::Unknown => json!({ "status": "unknown" }),
        };
        match &self.status {
            BatchItemStatus::Succeeded { pseudocode } => json!({
                "address": self.address,
                "procedure": procedure,
                "status": "ok",
                "pseudocode": pseudocode,
            }),
            BatchItemStatus::Failed { error } => {
                let error_value = error.to_json();
                let procedure = match &self.procedure {
                    ProcedureIdentity::Resolved(procedure) => json!({
                        "status": "resolved",
                        "address": procedure.address,
                        "name": procedure.name,
                    }),
                    ProcedureIdentity::Unknown => json!({
                        "status": "unknown",
                        "error": error_value,
                    }),
                };
                json!({
                    "address": self.address,
                    "procedure": procedure,
                    "status": "error",
                    "error": error_value,
                })
            }
        }
    }
}

impl BatchItemError {
    pub fn to_json(&self) -> Value {
        self.to_json_for_operation(BATCH_OPERATION)
    }

    /// Project the worker failure with the operation that owns the request.
    ///
    /// The default projection remains batch-decompile compatible, while
    /// runtime callers can preserve their selected operation without adding
    /// operation state to the public error struct.
    pub fn to_json_for_operation(&self, operation: &str) -> Value {
        let (code, category, details, remediation) = match &self.kind {
            BatchItemErrorKind::Deadline => (
                "provider_timeout",
                "timeout",
                json!({
                    "operation": operation,
                    "timeout_ms": self.timeout_ms,
                    "diagnostics": self.diagnostics(),
                }),
                TIMEOUT_REMEDIATION,
            ),
            BatchItemErrorKind::PseudocodeLimit => (
                "resource_constraint",
                "resource_constraint",
                json!({
                    "operation": operation,
                    "resource": "transport",
                    "reason": self.message,
                    "reported_limits": {
                        "pseudocode_bytes": MAX_PSEUDOCODE_BYTES,
                    },
                    "diagnostics": self.diagnostics(),
                }),
                TRANSPORT_REMEDIATION,
            ),
            BatchItemErrorKind::BatchOutputLimit => (
                "resource_constraint",
                "resource_constraint",
                json!({
                    "operation": operation,
                    "resource": "transport",
                    "reason": self.message,
                    "reported_limits": {
                        "batch_bytes": crate::ghidra_rust::protocol::MAX_BATCH_BYTES,
                    },
                    "diagnostics": self.diagnostics(),
                }),
                TRANSPORT_REMEDIATION,
            ),
            BatchItemErrorKind::Output => (
                "unreadable_output",
                "execution_failure",
                json!({
                    "operation": operation,
                    "reason": self.message,
                    "diagnostics": self.diagnostics(),
                }),
                OUTPUT_REMEDIATION,
            ),
        };
        json!({
            "code": code,
            "category": category,
            "message": self.message,
            "retryable": false,
            "remediation": { "action": remediation },
            "details": details,
        })
    }

    fn diagnostics(&self) -> Value {
        json!({ "worker_error_code": self.worker_error_code })
    }
}

fn validate_optional_bounded(
    value: &Option<String>,
    maximum: usize,
    label: &str,
) -> Result<(), String> {
    if let Some(value) = value {
        if value.len() > maximum {
            return Err(format!("{label} exceeds the bounded size"));
        }
    }
    Ok(())
}

fn validate_bounded(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.len() > maximum {
        return Err(format!("{label} exceeds the bounded size"));
    }
    Ok(())
}

fn require_nonempty_bounded(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > maximum {
        return Err(format!("{label} exceeds the bounded size"));
    }
    Ok(())
}
