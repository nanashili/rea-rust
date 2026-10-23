//! COFF machine decoding for PE fuse containers.
//!
//! Compatibility owner: `src/domain/peMachine.ts` (`decodePeMachine`,
//! `architectureForMachine`, `NATIVE_OS_OVERRIDES`). The fuse reader consumes
//! only the architecture, and rejects it when a managed OS override is present.

/// Maximum PE header offset the fuse reader will follow.
pub const MAXIMUM_PE_HEADER_OFFSET: usize = 1024 * 1024;

/// A decoded COFF machine and whether it carried a ReadyToRun OS override.
pub struct PeMachine {
    pub architecture: &'static str,
    pub native_os_override: bool,
}

fn architecture_for_machine(machine: u16) -> Option<&'static str> {
    match machine {
        0x014c => Some("x86"),
        0x8664 => Some("x86_64"),
        0x01c0 | 0x01c2 | 0x01c4 => Some("arm"),
        0xaa64 => Some("arm64"),
        _ => None,
    }
}

const NATIVE_OS_OVERRIDES: [u16; 6] = [0x4644, 0xadc4, 0xadc5, 0x7b79, 0x1993, 0x1992];

/// Decode a COFF machine. Only managed images carry an OS override, so callers
/// must reject `native_os_override` when the image has no CLI header.
pub fn decode_machine(machine: u16) -> Option<PeMachine> {
    if let Some(direct) = architecture_for_machine(machine) {
        return Some(PeMachine {
            architecture: direct,
            native_os_override: false,
        });
    }
    for over in NATIVE_OS_OVERRIDES {
        if let Some(architecture) = architecture_for_machine(machine ^ over) {
            return Some(PeMachine {
                architecture,
                native_os_override: true,
            });
        }
    }
    None
}
