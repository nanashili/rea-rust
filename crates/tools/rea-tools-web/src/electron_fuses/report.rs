//! Electron fuse wire decoding and runtime-implication derivation.
//!
//! Compatibility owner: `src/domain/electron/electronFuses.ts`
//! (`electronFuseState`, `electronFuseName`, `describeElectronFuseFindings`).
use serde::Serialize;
use serde_json::{Value, json};

/// ASCII sentinel that introduces an Electron fuse wire in an Electron binary.
pub const SENTINEL: &[u8] = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";

/// FuseV1 index order.
pub const V1_NAMES: [&str; 9] = [
    "RunAsNode",
    "EnableCookieEncryption",
    "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments",
    "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar",
    "LoadBrowserProcessSpecificV8Snapshot",
    "GrantFileProtocolExtraPrivileges",
    "WasmTrapHandlers",
];

const OTHER_MEANS_LIMITATION: &str = "Fuse state does not prove the application enables Inspector through other means, such as app.commandLine or a remote-debugging switch in application code.";
const MISSING_SENTINEL_LIMITATION: &str =
    "A missing sentinel means fuse state is unknown, not that every fuse is disabled.";

/// Container format reported by the reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    MachO,
    MachOUniversal,
    Pe,
    Elf,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MachO => "mach-o",
            Self::MachOUniversal => "mach-o-universal",
            Self::Pe => "pe",
            Self::Elf => "elf",
        }
    }

    /// Electron compiles embedded ASAR integrity validation for macOS and Windows only.
    fn embedded_asar_integrity_applies(self) -> bool {
        matches!(self, Self::MachO | Self::MachOUniversal | Self::Pe)
    }
}

/// One decoded fuse byte.
#[derive(Clone, Debug, Serialize)]
pub struct Fuse {
    pub index: usize,
    pub name: Option<&'static str>,
    pub state: &'static str,
    pub raw_byte: u8,
}

/// One decoded Electron fuse wire.
#[derive(Clone, Debug, Serialize)]
pub struct Sentinel {
    pub sentinel_offset: usize,
    pub wire_version: Option<u8>,
    pub declared_length: Option<u8>,
    pub fuses: Vec<Fuse>,
    pub complete: bool,
}

/// One container slice and its fuse wires. Offsets are file-absolute.
#[derive(Clone, Debug, Serialize)]
pub struct Slice {
    pub index: usize,
    pub file_offset: usize,
    pub size: usize,
    pub architecture: Option<String>,
    pub sentinel_count: usize,
    pub sentinels: Vec<Sentinel>,
}

/// Decode one fuse wire byte. Any other value stays unknown and keeps the raw byte.
pub fn fuse_state(byte: u8) -> &'static str {
    match byte {
        0x30 => "disabled",
        0x31 => "enabled",
        0x72 => "removed",
        _ => "unknown",
    }
}

/// Pinned version-1 name, or `None` when the wire version or index has no table entry.
pub fn fuse_name(wire_version: u8, index: usize) -> Option<&'static str> {
    if wire_version == 1 {
        V1_NAMES.get(index).copied()
    } else {
        None
    }
}

/// One derivation specification keyed by subject.
struct ImplicationSpec {
    subject: &'static str,
    fuse_index: usize,
    enabled: &'static str,
    inactive: &'static str,
}

const FUSE_IMPLICATIONS: [ImplicationSpec; 4] = [
    ImplicationSpec {
        subject: "node_cli_inspect_arguments",
        fuse_index: 3,
        enabled: "honored",
        inactive: "not_honored",
    },
    ImplicationSpec {
        subject: "electron_run_as_node",
        fuse_index: 0,
        enabled: "honored",
        inactive: "not_honored",
    },
    ImplicationSpec {
        subject: "embedded_asar_integrity_validation",
        fuse_index: 4,
        enabled: "enforced",
        inactive: "not_enforced",
    },
    ImplicationSpec {
        subject: "only_load_app_from_asar",
        fuse_index: 5,
        enabled: "restricted_to_app_asar",
        inactive: "not_restricted_to_app_asar",
    },
];

/// Derivations and reading limitations for one container's slices.
pub struct Findings {
    pub runtime_implications: Vec<Value>,
    pub limitations: Vec<String>,
}

/// Attach derivations and reading limitations without choosing among multiple sentinels.
///
/// Exact port of `describeElectronFuseFindings`.
pub fn describe_findings(slices: &[Slice], container: Format) -> Findings {
    let mut runtime_implications = Vec::new();
    let mut limitations = vec![
        OTHER_MEANS_LIMITATION.to_owned(),
        MISSING_SENTINEL_LIMITATION.to_owned(),
    ];
    for slice in slices {
        if slice.sentinel_count == 0 {
            limitations.push(format!(
                "Slice {} at file offset {} contains no Electron fuse sentinel; fuse state for that slice is unknown, not disabled.",
                slice.index, slice.file_offset
            ));
        } else if slice.sentinel_count > 1 {
            limitations.push(format!(
                "Slice {} at file offset {} contains {} Electron fuse sentinels; every sentinel is reported and none is selected.",
                slice.index, slice.file_offset, slice.sentinel_count
            ));
        }
        for sentinel in &slice.sentinels {
            describe_sentinel(
                slice.index,
                sentinel,
                container,
                &mut runtime_implications,
                &mut limitations,
            );
        }
    }
    Findings {
        runtime_implications,
        limitations,
    }
}

fn describe_sentinel(
    slice_index: usize,
    sentinel: &Sentinel,
    container: Format,
    implications: &mut Vec<Value>,
    limitations: &mut Vec<String>,
) {
    if !sentinel.complete {
        limitations.push(format!(
            "Electron fuse wire at file offset {} is truncated; fuse bytes past the slice stay unknown.",
            sentinel.sentinel_offset
        ));
    }
    let Some(wire_version) = sentinel.wire_version else {
        return;
    };
    if wire_version != 1 {
        limitations.push(format!(
            "Electron fuse wire at file offset {} uses wire version {}; version 1 is the only pinned name table, so runtime implications for this wire are unknown.",
            sentinel.sentinel_offset, wire_version
        ));
        return;
    }
    for spec in &FUSE_IMPLICATIONS {
        let Some(fuse) = sentinel
            .fuses
            .iter()
            .find(|item| item.index == spec.fuse_index)
        else {
            limitations.push(format!(
                "Electron fuse wire at file offset {} does not include fuse index {}; that runtime implication is unknown.",
                sentinel.sentinel_offset, spec.fuse_index
            ));
            continue;
        };
        let applicability_unknown = spec.subject == "embedded_asar_integrity_validation"
            && !container.embedded_asar_integrity_applies();
        if applicability_unknown {
            limitations.push(format!(
                "Electron compiles embedded ASAR integrity validation only on macOS and Windows; the observed fuse byte at file offset {} does not establish enforcement.",
                sentinel.sentinel_offset
            ));
        }
        let state = if applicability_unknown {
            "unknown"
        } else {
            fuse.state
        };
        let outcome = if state == "enabled" {
            spec.enabled
        } else if state == "unknown" {
            "unknown"
        } else {
            spec.inactive
        };
        implications.push(json!({
            "relationship": "derivation",
            "subject": spec.subject,
            "fuse_index": spec.fuse_index,
            "outcome": outcome,
            "slice_index": slice_index,
            "sentinel_offset": sentinel.sentinel_offset,
        }));
    }
}
