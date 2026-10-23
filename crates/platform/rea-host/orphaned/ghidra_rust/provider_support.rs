//! Provider-neutral support facts for the optional Rust Ghidra adapter.
//!
//! This module only classifies caller-supplied facts.  It does not inspect a
//! target, start a worker, or choose a provider.  Keeping admission here makes
//! the Rust host agree with the TypeScript adapter before profile resolution.

use std::collections::BTreeMap;

pub const PROVIDER_ID: &str = "ghidra-rust";
pub const PROVIDER_NAME: &str = "Ghidra Rust";
pub const PROVIDER_VERSION: &str = "worker-protocol-2";

const SUPPORTED_ARCHITECTURES: &[&str] = &["x86", "x86_64", "arm", "arm64"];

pub const OPERATIONS: &[&str] = &[
    "list_segments",
    "list_procedures",
    "search_procedures",
    "batch_decompile",
    "procedure_pseudo_code",
    "procedure_address",
    "address_name",
    "list_documents",
    "current_document",
];

pub const LIMITATIONS: &[&str] = &[
    "Functions come from the saved inventory or initial loader symbols and entry/function-start metadata; no function discovery is performed.",
    "This provider has no Java analyzers, Objective-C or Swift analysis, or type editor.",
    "Procedure search matches literal saved-inventory names only.",
    "Segment entries describe object-file sections; memory permissions are unavailable.",
    "Worker commands are attested by info: open, segments, functions, resolve_functions, batch_decompile, batch_decompile_inventory, checkpoint and close. REA resolves selectors against the frozen inventory and routes pseudocode through batch_decompile.",
    "Experimental local adapter; provider registration and distribution require a maintainer scope decision.",
    "The worker has an operation deadline and bounded output. Optional REA_GHIDRA_RUST_MEMORY_MIB supervision samples the exact worker process RSS on macOS/Linux and stops the owned process group when its threshold is reached or monitoring fails. This is not a kernel memory ceiling or a process-family memory limit; memory may overshoot between samples or during termination, and shared pages may be counted in RSS.",
    "RSS supervision samples at one-second intervals after each completed observation, with a one-second observation deadline. Scheduling and cleanup can delay termination. Termination preserves completed durable checkpoints; the current native call cannot safely checkpoint before it is stopped.",
    "The local prototype requires REA_GHIDRA_RUST_ENABLED=true. Public batches use sequential 64-procedure native chunks, a 16 MiB selector/inventory budget and a 32 MiB normalized output budget.",
    "Progress delivery is best-effort and coalesced. Worker replies and shutdown never wait for a stalled callback. A callback already in flight cannot be cancelled by the reporter interface.",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityStatus {
    Available,
    Unavailable(String),
    Unknown(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capability {
    pub operation: &'static str,
    pub status: CapabilityStatus,
    pub cache_policy: &'static str,
    pub mutates_artifact: bool,
    pub launches_process: bool,
    pub may_show_ui: bool,
    pub may_access_network: bool,
    pub may_write_filesystem: bool,
    pub changes_permissions: bool,
    pub requires_root: bool,
    pub limitations: &'static [&'static str],
}

/// Project one provider availability observation onto every supported
/// operation. Capability inspection itself never starts the worker.
pub fn capabilities_for_status(status: CapabilityStatus) -> Vec<Capability> {
    OPERATIONS
        .iter()
        .map(|operation| Capability {
            operation: *operation,
            status: status.clone(),
            cache_policy: "live",
            mutates_artifact: false,
            launches_process: true,
            may_show_ui: false,
            may_access_network: false,
            may_write_filesystem: true,
            changes_permissions: false,
            requires_root: false,
            limitations: LIMITATIONS,
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetFacts<'a> {
    pub kind: &'a str,
    pub format: &'a str,
    pub architecture: &'a str,
    pub managed: bool,
    pub executable_role: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetSupportCode {
    TargetKindUnsupported,
    TargetFormatUnsupported,
    ArchitectureUnsupported,
    TargetRoleUnsupported,
    ManagedTargetUnsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetSupport {
    pub supported: bool,
    pub code: Option<TargetSupportCode>,
    pub reason: Option<String>,
    pub diagnostics: BTreeMap<String, String>,
}

/// Inspect the already-normalized environment without starting a worker.
///
/// Configuration parsing and executable checks remain owned by the
/// configuration module; this forwarding function gives discovery one support
/// boundary for both environment and target observations.
pub fn inspect_availability(
    environment: &BTreeMap<String, String>,
) -> crate::ghidra_rust::configuration::Availability {
    crate::ghidra_rust::configuration::inspect_environment(environment)
}

/// Classify a target using metadata established by the target resolver.
///
/// The Rust host intentionally does not reopen or reinterpret the target at
/// this boundary.  In particular, a universal Mach-O remains unsupported;
/// callers must provide the selected thin slice as a separate target.
pub fn inspect_target_support(target: TargetFacts<'_>) -> TargetSupport {
    let diagnostics = target_diagnostics(target);

    if target.kind != "executable" {
        return unsupported(
            diagnostics,
            TargetSupportCode::TargetKindUnsupported,
            "Rust Ghidra opens native executable images.",
        );
    }

    if !matches!(target.format, "elf" | "pe" | "mach-o") {
        return unsupported(
            diagnostics,
            TargetSupportCode::TargetFormatUnsupported,
            "Rust Ghidra admits thin ELF, PE and Mach-O images. Extract a thin slice before opening a universal Mach-O.",
        );
    }

    if target.format == "pe" && target.managed {
        return unsupported(
            diagnostics,
            TargetSupportCode::ManagedTargetUnsupported,
            "Managed PE images require REA's managed provider.",
        );
    }

    if target.format == "pe" && target.executable_role == Some("non-executable") {
        return unsupported(
            diagnostics,
            TargetSupportCode::TargetRoleUnsupported,
            "The Rust worker requires a native executable image, not a PE object file.",
        );
    }

    if !SUPPORTED_ARCHITECTURES.contains(&target.architecture) {
        return unsupported(
            diagnostics,
            TargetSupportCode::ArchitectureUnsupported,
            &format!(
                "The Rust worker does not admit {}.",
                target.architecture
            ),
        );
    }

    TargetSupport {
        supported: true,
        code: None,
        reason: None,
        diagnostics,
    }
}

fn target_diagnostics(target: TargetFacts<'_>) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("target_kind".into(), target.kind.into()),
        ("target_format".into(), target.format.into()),
    ])
}

fn unsupported(
    diagnostics: BTreeMap<String, String>,
    code: TargetSupportCode,
    reason: &str,
) -> TargetSupport {
    TargetSupport {
        supported: false,
        code: Some(code),
        reason: Some(reason.into()),
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::{TargetFacts, TargetSupportCode, inspect_target_support};

    fn executable(format: &'static str, architecture: &'static str) -> TargetFacts<'static> {
        TargetFacts {
            kind: "executable",
            format,
            architecture,
            managed: false,
            executable_role: Some("application"),
        }
    }

    #[test]
    fn admits_supported_native_executable() {
        let support = inspect_target_support(executable("elf", "x86_64"));

        assert!(support.supported);
        assert_eq!(support.code, None);
        assert_eq!(support.reason, None);
    }

    #[test]
    fn rejects_universal_macho_before_architecture() {
        let support = inspect_target_support(executable("mach-o-universal", "arm64"));

        assert_eq!(
            support.code,
            Some(TargetSupportCode::TargetFormatUnsupported)
        );
    }

    #[test]
    fn rejects_managed_pe() {
        let support = inspect_target_support(TargetFacts {
            managed: true,
            ..executable("pe", "x86_64")
        });

        assert_eq!(
            support.code,
            Some(TargetSupportCode::ManagedTargetUnsupported)
        );
    }

    #[test]
    fn rejects_pe_object_files() {
        let support = inspect_target_support(TargetFacts {
            executable_role: Some("non-executable"),
            ..executable("pe", "x86_64")
        });

        assert_eq!(support.code, Some(TargetSupportCode::TargetRoleUnsupported));
    }
}
