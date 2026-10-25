//! Provider identity, declared operations, limitations and target admission.
//!
//! Compatibility owner: `src/ghidra-rust/GhidraRustCapabilities.ts`.
use rea_analysis::{
    BinaryTarget, CapabilityDescriptor, CapabilityEffects, ProviderIdentity, TargetSupport,
};
use serde_json::{Map, Value, json};

pub(crate) const PROVIDER_ID: &str = "ghidra-rust";
pub(crate) const PROVIDER_NAME: &str = "Ghidra Rust";
pub(crate) const PROVIDER_VERSION: &str = "worker-protocol-2";

/// `GHIDRA_RUST_IDENTITY`.
pub(crate) fn identity() -> ProviderIdentity {
    ProviderIdentity::new(
        PROVIDER_ID,
        PROVIDER_NAME,
        Some(PROVIDER_VERSION.to_owned()),
    )
}

/// `GHIDRA_RUST_LIMITATIONS`.
///
/// This is REA's only Ghidra provider and is enabled by default, so the batch
/// limitation states only the budgets that still apply.
pub(crate) const LIMITATIONS: [&str; 11] = [
    "Functions come from the saved inventory or initial loader symbols and entry/function-start metadata; no function discovery is performed.",
    "This provider has no Java analyzers, Objective-C or Swift analysis, or type editor.",
    "Procedure search matches literal saved-inventory names only, including aliases: additional loader symbols at an entry address, such as identical-code-folded functions. list_procedures has one row per entry address with its primary name; an alias selector resolves to that entry.",
    "list_names exposes the same frozen procedure inventory plus validated loader aliases; imported, exported, and other symbol-table names outside that inventory are not included.",
    "Segment entries describe object-file sections; memory permissions are unavailable.",
    "Worker commands are attested by info: open, segments, image_map, search_bytes, functions, function_aliases, resolve_functions, batch_decompile, batch_decompile_inventory, strings, references_to, references_from, instructions, inspect_instruction, read_bytes, checkpoint and close. REA resolves selectors against the frozen inventory and routes pseudocode through batch_decompile.",
    "Strings, references, callers and callees are derived by the worker (see its limitations): references come from a linear p-code pass with register constant propagation, not Ghidra's reference manager, so indirect targets and references through memory are absent. Reference types and operand indexes are not recorded, function bodies are not recovered, and annotations are not supported.",
    "The worker has an operation deadline and bounded output. Optional REA_GHIDRA_RUST_MEMORY_MIB supervision samples the exact worker process RSS on macOS/Linux and stops the owned process group when its threshold is reached or monitoring fails. This is not a kernel memory ceiling or a process-family memory limit; memory may overshoot between samples or during termination, and shared pages may be counted in RSS.",
    "RSS supervision samples at one-second intervals after each completed observation, with a one-second observation deadline. Scheduling and cleanup can delay termination. Termination preserves completed durable checkpoints; the current native call cannot safely checkpoint before it is stopped.",
    "Public batches use sequential 64-procedure native chunks, a 16 MiB selector budget and a 32 MiB normalized output budget. The procedure inventory is bounded by the worker frozen-inventory limits (1,000,000 functions and 32 MiB of names); MCP delivers an oversized inventory as retained Evidence pages.",
    "Progress delivery is best-effort and coalesced. Worker replies and shutdown never wait for a stalled callback. A callback already in flight cannot be cancelled by the reporter interface.",
];

pub(crate) fn limitations() -> Vec<String> {
    LIMITATIONS.iter().map(|text| (*text).to_owned()).collect()
}

/// `GHIDRA_RUST_OPERATIONS`, in the declared order.
pub(crate) const OPERATIONS: [&str; 23] = [
    "list_segments",
    "list_procedures",
    "search_procedures",
    "batch_decompile",
    "procedure_pseudo_code",
    "procedure_address",
    "address_name",
    "list_documents",
    "current_document",
    "list_strings",
    "search_strings",
    "xrefs",
    "procedure_callers",
    "procedure_callees",
    "procedure_references",
    "procedure_assembly",
    "read_function_instructions",
    "read_bytes",
    "list_names",
    "analyze_function",
    "address_to_file_offset",
    "search_bytes",
    "inspect_native_instruction",
];

/// One declared operation (or the internal health probe).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
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
    ListStrings,
    SearchStrings,
    Xrefs,
    ProcedureCallers,
    ProcedureCallees,
    ProcedureReferences,
    ProcedureAssembly,
    ReadFunctionInstructions,
    ReadBytes,
    ListNames,
    AnalyzeFunction,
    AddressToFileOffset,
    SearchBytes,
    InspectNativeInstruction,
}

impl Operation {
    pub(crate) fn parse(operation: &str) -> Option<Self> {
        Some(match operation {
            "health" => Self::Health,
            "list_segments" => Self::ListSegments,
            "list_procedures" => Self::ListProcedures,
            "search_procedures" => Self::SearchProcedures,
            "batch_decompile" => Self::BatchDecompile,
            "procedure_pseudo_code" => Self::ProcedurePseudoCode,
            "procedure_address" => Self::ProcedureAddress,
            "address_name" => Self::AddressName,
            "list_documents" => Self::ListDocuments,
            "current_document" => Self::CurrentDocument,
            "list_strings" => Self::ListStrings,
            "search_strings" => Self::SearchStrings,
            "xrefs" => Self::Xrefs,
            "procedure_callers" => Self::ProcedureCallers,
            "procedure_callees" => Self::ProcedureCallees,
            "procedure_references" => Self::ProcedureReferences,
            "procedure_assembly" => Self::ProcedureAssembly,
            "read_function_instructions" => Self::ReadFunctionInstructions,
            "read_bytes" => Self::ReadBytes,
            "list_names" => Self::ListNames,
            "analyze_function" => Self::AnalyzeFunction,
            "address_to_file_offset" => Self::AddressToFileOffset,
            "search_bytes" => Self::SearchBytes,
            "inspect_native_instruction" => Self::InspectNativeInstruction,
            _ => return None,
        })
    }

    pub(crate) fn name(self) -> &'static str {
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
            Self::ListStrings => "list_strings",
            Self::SearchStrings => "search_strings",
            Self::Xrefs => "xrefs",
            Self::ProcedureCallers => "procedure_callers",
            Self::ProcedureCallees => "procedure_callees",
            Self::ProcedureReferences => "procedure_references",
            Self::ProcedureAssembly => "procedure_assembly",
            Self::ReadFunctionInstructions => "read_function_instructions",
            Self::ReadBytes => "read_bytes",
            Self::ListNames => "list_names",
            Self::AnalyzeFunction => "analyze_function",
            Self::AddressToFileOffset => "address_to_file_offset",
            Self::SearchBytes => "search_bytes",
            Self::InspectNativeInstruction => "inspect_native_instruction",
        }
    }
}

/// `ghidraRustCapabilities(availability)`.
pub(crate) fn capabilities(reason: Option<&str>) -> Vec<CapabilityDescriptor> {
    OPERATIONS
        .iter()
        .map(|operation| CapabilityDescriptor {
            operation: (*operation).to_owned(),
            available: reason.is_none(),
            reason: reason.map(str::to_owned),
            availability_code: None,
            cache_policy: Some("live".to_owned()),
            provider: identity(),
            effects: CapabilityEffects {
                mutates_artifact: false,
                launches_process: true,
                may_show_ui: false,
                may_access_network: false,
                may_write_filesystem: true,
                changes_permissions: false,
                requires_root: false,
            },
            limitations: limitations(),
        })
        .collect()
}

const ARCHITECTURES: [&str; 4] = ["x86", "x86_64", "arm", "arm64"];

/// `inspectGhidraRustTargetSupport`.
pub(crate) fn target_support(target: &BinaryTarget) -> TargetSupport {
    let mut diagnostics = Map::new();
    diagnostics.insert("target_kind".into(), json!(target.kind));
    diagnostics.insert("target_format".into(), json!(target.format));
    let unsupported = |code: &str, reason: String| TargetSupport::Unsupported {
        code: code.to_owned(),
        reason,
        diagnostics: diagnostics.clone(),
    };
    if target.kind != "executable" {
        return unsupported(
            "target_kind_unsupported",
            "Rust Ghidra opens native executable images.".into(),
        );
    }
    if !matches!(
        target.format.as_str(),
        "elf" | "pe" | "mach-o" | "mach-o-universal"
    ) {
        return unsupported(
            "target_format_unsupported",
            "Rust Ghidra admits ELF, PE, thin Mach-O, and universal Mach-O images.".into(),
        );
    }
    if target.format == "pe" && target.metadata.get("managed") == Some(&Value::Bool(true)) {
        return unsupported(
            "managed_target_unsupported",
            "Managed PE images require REA's managed provider.".into(),
        );
    }
    if target.format == "pe"
        && target
            .metadata
            .get("executableRole")
            .and_then(Value::as_str)
            == Some("non-executable")
    {
        return unsupported(
            "target_role_unsupported",
            "The Rust worker requires a native executable image, not a PE object file.".into(),
        );
    }
    let architecture = target.architecture.as_deref().unwrap_or("undefined");
    if !ARCHITECTURES.contains(&architecture) {
        return unsupported(
            "architecture_unsupported",
            format!("The Rust worker does not admit {architecture}."),
        );
    }
    TargetSupport::Supported { diagnostics }
}
