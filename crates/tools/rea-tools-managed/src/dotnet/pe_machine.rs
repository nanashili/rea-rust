//! COFF machine decoding with ReadyToRun OS override detection.
//!
//! Port of `src/domain/peMachine.ts`, restricted to the PE architectures the
//! managed reader uses (`hexagon` is excluded upstream).

/// A PE architecture the managed reader recognizes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PeArchitecture {
    X86,
    X86_64,
    Arm,
    Arm64,
}

impl PeArchitecture {
    pub fn as_str(self) -> &'static str {
        match self {
            PeArchitecture::X86 => "x86",
            PeArchitecture::X86_64 => "x86_64",
            PeArchitecture::Arm => "arm",
            PeArchitecture::Arm64 => "arm64",
        }
    }
}

/// A decoded COFF machine and whether it carried a ReadyToRun OS override.
pub struct PeMachine {
    pub architecture: PeArchitecture,
    pub native_os_override: bool,
}

fn architecture_for_machine(machine: u32) -> Option<PeArchitecture> {
    match machine {
        0x014c => Some(PeArchitecture::X86),
        0x8664 => Some(PeArchitecture::X86_64),
        0x01c0 | 0x01c2 | 0x01c4 => Some(PeArchitecture::Arm),
        0xaa64 => Some(PeArchitecture::Arm64),
        _ => None,
    }
}

/// ReadyToRun images compiled for a non-Windows OS XOR the COFF machine with
/// one of these overrides (Apple, FreeBSD, OpenBSD, Linux, NetBSD, SunOS).
const NATIVE_OS_OVERRIDES: [u32; 6] = [0x4644, 0xadc4, 0xadc5, 0x7b79, 0x1993, 0x1992];

/// Decode a COFF machine. Only managed images carry an OS override, so callers
/// must reject `native_os_override` when the image has no CLI header.
pub fn decode_pe_machine(machine: u32) -> Option<PeMachine> {
    if let Some(direct) = architecture_for_machine(machine) {
        return Some(PeMachine {
            architecture: direct,
            native_os_override: false,
        });
    }
    for override_mask in NATIVE_OS_OVERRIDES {
        if let Some(architecture) = architecture_for_machine(machine ^ override_mask) {
            return Some(PeMachine {
                architecture,
                native_os_override: true,
            });
        }
    }
    None
}
