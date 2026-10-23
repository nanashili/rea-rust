//! Port of `src/native/MachoArchitectureSelection.ts` and the
//! `selectArchitecture` helper of `src/native/NativeMachoInspection.ts`.

use crate::lipo::LipoArchitecture;
use rea_analysis::BinaryTarget;

/// `machoCpuSubtypeBase`: CPU subtype identity shared across capability-flag
/// variations (`CPU_SUBTYPE_CAPABILITY_MASK = 0xff000000`).
fn macho_cpu_subtype_base(cpu_subtype: u64) -> u64 {
    cpu_subtype & !0xff00_0000
}

/// One named subtype inside a policy.
struct NamedSubtype {
    subtype: u64,
    name: &'static str,
}

/// `MachoArchitecturePolicy`.
struct MachoArchitecturePolicy {
    cpu_type: u64,
    subtypes: &'static [NamedSubtype],
    /// Matches a variant slice name (for example `arm64e.x1`).
    variant_name: Option<fn(&str) -> bool>,
}

fn is_arm_variant(name: &str) -> bool {
    name == "arm"
}

fn is_arm64e_variant(name: &str) -> bool {
    // `^arm64e\.[A-Za-z0-9_]+$`.
    let Some(rest) = name.strip_prefix("arm64e.") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// `MACHO_ARCHITECTURE_POLICIES[architecture]`.
fn macho_architecture_policy(architecture: &str) -> Option<MachoArchitecturePolicy> {
    Some(match architecture {
        "x86" => MachoArchitecturePolicy {
            cpu_type: 7,
            subtypes: &[NamedSubtype {
                subtype: 3,
                name: "i386",
            }],
            variant_name: None,
        },
        "x86_64" => MachoArchitecturePolicy {
            cpu_type: 0x0100_0007,
            subtypes: &[NamedSubtype {
                subtype: 3,
                name: "x86_64",
            }],
            variant_name: None,
        },
        "arm" => MachoArchitecturePolicy {
            cpu_type: 12,
            subtypes: &[],
            variant_name: Some(is_arm_variant),
        },
        "arm64" => MachoArchitecturePolicy {
            cpu_type: 0x0100_000c,
            subtypes: &[
                NamedSubtype {
                    subtype: 0,
                    name: "arm64",
                },
                NamedSubtype {
                    subtype: 2,
                    name: "arm64e",
                },
                NamedSubtype {
                    subtype: 1,
                    name: "arm64v8",
                },
            ],
            variant_name: Some(is_arm64e_variant),
        },
        _ => return None,
    })
}

/// `machoSubtypeRank(policy, subtype)`: unlisted subtypes follow the preferred
/// slices in FAT table order.
fn macho_subtype_rank(policy: &MachoArchitecturePolicy, subtype: u64) -> usize {
    let base = macho_cpu_subtype_base(subtype);
    policy
        .subtypes
        .iter()
        .position(|candidate| candidate.subtype == base)
        .unwrap_or(policy.subtypes.len())
}

/// `selectMachoArchitectureName(policy, available)`.
fn select_macho_architecture_name(
    policy: &MachoArchitecturePolicy,
    available: &[LipoArchitecture],
) -> Option<String> {
    let mut selected: Option<String> = None;
    // `Number.POSITIVE_INFINITY` sentinel: nothing selected yet.
    let mut best_rank: Option<usize> = None;
    for architecture in available {
        if let Some(code) = architecture.cpu_type_code
            && code != policy.cpu_type
        {
            continue;
        }
        let named_subtype = policy
            .subtypes
            .iter()
            .find(|candidate| candidate.name == architecture.name);
        let recognized_name = named_subtype.is_some()
            || policy
                .variant_name
                .is_some_and(|matcher| matcher(&architecture.name));
        if !recognized_name
            && (architecture.cpu_type_code.is_none() || architecture.cpu_subtype_base.is_none())
        {
            continue;
        }
        // Parsed identity is authoritative. Names support thin/partial records.
        let subtype = architecture
            .cpu_subtype_base
            .or_else(|| named_subtype.map(|candidate| candidate.subtype));
        let rank = match subtype {
            None => policy.subtypes.len(),
            Some(subtype) => macho_subtype_rank(policy, subtype),
        };
        if best_rank.is_some_and(|best| rank >= best) {
            continue;
        }
        selected = Some(architecture.name.clone());
        best_rank = Some(rank);
    }
    selected
}

/// Outcome of architecture selection (`ArchitectureSelection`).
pub(crate) enum ArchitectureSelection {
    Unfiltered,
    Selected(String),
    Absent(String),
}

/// `selectArchitecture(target, available)`.
pub(crate) fn select_architecture(
    target: &BinaryTarget,
    available: &[LipoArchitecture],
) -> ArchitectureSelection {
    // BinaryTarget lists CPU families and lipo lists slices. A universal file
    // can hold several slices of one family (arm64e and arm64e.x1), and slice
    // tools without -arch print every slice.
    if target.kind != "executable"
        || (target.available_architectures.len() < 2 && available.len() < 2)
    {
        return ArchitectureSelection::Unfiltered;
    }
    let architecture = target.architecture.as_deref().unwrap_or("");
    let normalized = if architecture == "x86" {
        "i386".to_owned()
    } else {
        architecture.to_owned()
    };
    let policy = macho_architecture_policy(architecture);
    let selected = match &policy {
        None => available
            .iter()
            .find(|candidate| candidate.name == normalized)
            .map(|candidate| candidate.name.clone()),
        Some(policy) => select_macho_architecture_name(policy, available),
    };
    match selected {
        Some(selected) => ArchitectureSelection::Selected(selected),
        None => ArchitectureSelection::Absent(normalized),
    }
}

/// `toolArchitectureName(tool, architecture)`.
///
/// lipo appends the pointer-auth ABI version to arm64e (`arm64e.v1`). Only
/// dyld_info accepts that spelling; the other Apple tools select the slice by
/// its CPU-family name.
pub(crate) fn tool_architecture_name(tool: &str, architecture: &str) -> String {
    if tool == "dyld_info" {
        return architecture.to_owned();
    }
    // Strip a trailing `.v<digits>` suffix.
    if let Some(dot) = architecture.rfind(".v") {
        let suffix = &architecture[dot + 2..];
        if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return architecture[..dot].to_owned();
        }
    }
    architecture.to_owned()
}

/// `selectedArchitectureArguments(tool, architecture)`.
pub(crate) fn selected_architecture_arguments(
    tool: &str,
    architecture: Option<&str>,
) -> Vec<String> {
    let Some(architecture) = architecture else {
        return Vec::new();
    };
    let tool_architecture = tool_architecture_name(tool, architecture);
    if tool == "dwarfdump" {
        vec![format!("--arch={tool_architecture}")]
    } else {
        vec!["-arch".to_owned(), tool_architecture]
    }
}
