//! Selector validation and provenance decisions for the Rust Ghidra worker.
//!
//! The transport owns JSON framing and the application owns user-facing error
//! conversion.  This module keeps the selector contract in one place so those
//! layers cannot disagree about ordering, identity, or ambiguity.

use serde_json::json;

use crate::ghidra_rust::protocol::{
    self as protocol, WorkerFunctionResolution, WorkerResolution,
};

const REQUEST_ENVELOPE_RESERVE: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorOperation {
    ProcedureAddress,
    ProcedurePseudoCode,
    BatchDecompile,
    AddressName,
}

impl SelectorOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcedureAddress => "procedure_address",
            Self::ProcedurePseudoCode => "procedure_pseudo_code",
            Self::BatchDecompile => "batch_decompile",
            Self::AddressName => "address_name",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorOrigin {
    Caller,
    Provider,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorFailureKind {
    Input,
    Output,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectorFailure {
    pub operation: SelectorOperation,
    pub kind: SelectorFailureKind,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectorValidationError {
    Capacity {
        maximum_selectors: usize,
        maximum_request_bytes: usize,
    },
    ResponseShape(&'static str),
    InventoryMismatch,
    RequestMismatch { index: usize },
    InvalidFoundItem { index: usize },
    InvalidUnresolvedItem { index: usize },
}

impl std::fmt::Display for SelectorValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Capacity { .. } => {
                formatter.write_str("selector resolution exceeds its bounded request capacity")
            }
            Self::ResponseShape(message) => formatter.write_str(message),
            Self::InventoryMismatch => formatter.write_str(
                "selector resolution inventory differs from the frozen inventory",
            ),
            Self::RequestMismatch { .. } => {
                formatter.write_str("selector resolution differs from the request")
            }
            Self::InvalidFoundItem { .. } => {
                formatter.write_str("found selector results require both address and name")
            }
            Self::InvalidUnresolvedItem { .. } => {
                formatter.write_str("unresolved selector results must omit address and name")
            }
        }
    }
}

impl std::error::Error for SelectorValidationError {}

/// Validate the same selector count and serialized request budget as TypeScript.
pub fn validate_resolution_request(selectors: &[String]) -> Result<(), SelectorValidationError> {
    let request_bytes = serde_json::to_vec(&json!({ "selectors": selectors }))
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    if selectors.is_empty()
        || selectors.len() > protocol::MAX_RESOLUTION_SELECTORS
        || request_bytes.saturating_add(REQUEST_ENVELOPE_RESERVE) > protocol::MAX_REQUEST_BYTES
    {
        return Err(SelectorValidationError::Capacity {
            maximum_selectors: protocol::MAX_RESOLUTION_SELECTORS,
            maximum_request_bytes: protocol::MAX_REQUEST_BYTES,
        });
    }
    Ok(())
}

/// Require response ordering and identity to match the frozen selector request.
pub fn validate_resolution<'a>(
    response: &'a WorkerResolution,
    selectors: &[String],
    inventory_sha256: &str,
) -> Result<&'a [WorkerFunctionResolution], SelectorValidationError> {
    if response.inventory_sha256 != inventory_sha256 {
        return Err(SelectorValidationError::InventoryMismatch);
    }
    if response.items.len() != selectors.len() {
        return Err(SelectorValidationError::ResponseShape(
            "selector resolution returned an unexpected item count",
        ));
    }
    for (index, (item, selector)) in response.items.iter().zip(selectors).enumerate() {
        if item.selector != *selector {
            return Err(SelectorValidationError::RequestMismatch { index });
        }
        let resolved = item.address.is_some() && item.name.is_some();
        let unresolved = item.address.is_none() && item.name.is_none();
        match item.status.as_str() {
            "found" if resolved => {}
            "found" => return Err(SelectorValidationError::InvalidFoundItem { index }),
            "not_found" | "ambiguous" if unresolved => {}
            "not_found" | "ambiguous" => {
                return Err(SelectorValidationError::InvalidUnresolvedItem { index });
            }
            _ => {
                return Err(SelectorValidationError::ResponseShape(
                    "selector resolution status is invalid",
                ));
            }
        }
    }
    Ok(&response.items)
}

pub fn selector_failure(
    operation: SelectorOperation,
    status: &str,
    origin: SelectorOrigin,
) -> SelectorFailure {
    let reason = if status == "ambiguous" {
        "The function name is ambiguous; select an inventory address."
    } else {
        "The selector is outside the frozen function inventory."
    };
    SelectorFailure {
        operation,
        kind: if origin == SelectorOrigin::Provider {
            SelectorFailureKind::Output
        } else {
            SelectorFailureKind::Input
        },
        reason,
    }
}

