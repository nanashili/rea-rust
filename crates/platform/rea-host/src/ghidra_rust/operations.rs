//! Ordered operation selection for the optional Rust Ghidra provider.
//!
//! The public operation order is part of the provider contract.  Keeping it
//! here prevents capability discovery and dispatch code from each inventing a
//! slightly different list.  Worker methods are named separately because
//! several public operations are projections over the same worker command.

use crate::ghidra_rust::protocol::WorkerRequest;

pub const PUBLIC_OPERATIONS: &[GhidraRustOperation] = &[
    GhidraRustOperation::ListSegments,
    GhidraRustOperation::ListProcedures,
    GhidraRustOperation::SearchProcedures,
    GhidraRustOperation::BatchDecompile,
    GhidraRustOperation::ProcedurePseudoCode,
    GhidraRustOperation::ProcedureAddress,
    GhidraRustOperation::AddressName,
    GhidraRustOperation::ListDocuments,
    GhidraRustOperation::CurrentDocument,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GhidraRustOperation {
    Health,
    ListSegments,
    ListProcedures,
    SearchProcedures,
    BatchDecompile,
    ProcedurePseudoCode,
    ProcedureAddress,
    AddressName,
    ListDocuments,
    CurrentDocument,
}

impl GhidraRustOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::ListSegments => "list_segments",
            Self::ListProcedures => "list_procedures",
            Self::SearchProcedures => "search_procedures",
            Self::BatchDecompile => "batch_decompile",
            Self::ProcedurePseudoCode => "procedure_pseudo_code",
            Self::ProcedureAddress => "procedure_address",
            Self::AddressName => "address_name",
            Self::ListDocuments => "list_documents",
            Self::CurrentDocument => "current_document",
        }
    }

    pub const fn is_public(self) -> bool {
        !matches!(self, Self::Health)
    }

    /// The TypeScript provider handles these operations from the prepared
    /// session and target facts rather than by sending a worker command.
    /// Keeping this distinction explicit prevents local reads from being
    /// mistaken for unsupported public capabilities.
    pub const fn is_local(self) -> bool {
        matches!(
            self,
            Self::Health | Self::ListDocuments | Self::CurrentDocument
        )
    }

    pub const fn is_worker_backed(self) -> bool {
        self.worker_method().is_some()
    }

    /// Whether the operation needs request-specific worker input before it
    /// can be dispatched.
    pub const fn requires_input(self) -> bool {
        matches!(
            self,
            Self::ListProcedures
                | Self::SearchProcedures
                | Self::BatchDecompile
                | Self::ProcedurePseudoCode
                | Self::ProcedureAddress
                | Self::AddressName
        )
    }

    pub const fn worker_method(self) -> Option<&'static str> {
        match self {
            Self::Health | Self::ListDocuments | Self::CurrentDocument => None,
            Self::ListSegments => Some("segments"),
            Self::ListProcedures => Some("functions"),
            Self::SearchProcedures | Self::ProcedureAddress | Self::AddressName => {
                Some("resolve_functions")
            }
            Self::BatchDecompile | Self::ProcedurePseudoCode => Some("batch_decompile"),
        }
    }

    pub fn parse(value: &str) -> Result<Self, OperationSelectionError> {
        match value {
            "health" => Ok(Self::Health),
            "list_segments" => Ok(Self::ListSegments),
            "list_procedures" => Ok(Self::ListProcedures),
            "search_procedures" => Ok(Self::SearchProcedures),
            "batch_decompile" => Ok(Self::BatchDecompile),
            "procedure_pseudo_code" => Ok(Self::ProcedurePseudoCode),
            "procedure_address" => Ok(Self::ProcedureAddress),
            "address_name" => Ok(Self::AddressName),
            "list_documents" => Ok(Self::ListDocuments),
            "current_document" => Ok(Self::CurrentDocument),
            other => Err(OperationSelectionError::Unsupported(other.to_owned())),
        }
    }

    pub fn ordered_public() -> &'static [Self] {
        PUBLIC_OPERATIONS
    }

    /// Construct a request for operations that map directly to a worker call.
    /// Higher-level projections must validate their own input before using the
    /// corresponding worker request constructor.
    pub fn empty_request(self, id: u64) -> Result<Option<WorkerRequest>, OperationSelectionError> {
        let request = match self {
            Self::ListSegments => Some(WorkerRequest::segments(id)),
            Self::Health | Self::ListDocuments | Self::CurrentDocument => None,
            Self::ListProcedures
            | Self::SearchProcedures
            | Self::BatchDecompile
            | Self::ProcedurePseudoCode
            | Self::ProcedureAddress
            | Self::AddressName => {
                return Err(OperationSelectionError::InputRequired(self));
            }
        };

        request
            .transpose()
            .map_err(OperationSelectionError::InvalidRequest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationSelectionError {
    Unsupported(String),
    InputRequired(GhidraRustOperation),
    InvalidRequest(String),
}

impl std::fmt::Display for OperationSelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(operation) => {
                write!(formatter, "unsupported Ghidra Rust operation: {operation}")
            }
            Self::InputRequired(operation) => {
                write!(
                    formatter,
                    "Ghidra Rust operation requires input: {}",
                    operation.as_str()
                )
            }
            Self::InvalidRequest(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for OperationSelectionError {}
