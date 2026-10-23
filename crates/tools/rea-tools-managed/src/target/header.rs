//! Pure executable-header parsing without I/O.
//!
//! Ports `src/domain/binaryTarget.ts` `parseExecutableHeader` and its
//! dispatch to ELF / Mach-O (thin + FAT) / MZ-PE / DOS-MZ parsers, plus the
//! shared `ExecutableMetadata` shape from `binaryTarget.ts`.

use serde_json::{Map, Value, json};

use super::elf;
use super::macho;
use super::pe;

/// Format and architecture facts recovered from an executable header.
///
/// Mirrors the TS `ExecutableMetadata` union. `format`, `architecture` and
/// `available_architectures` map directly to `BinaryTarget`; the remaining
/// variant facts are emitted into `metadata` with the original camelCase keys.
#[derive(Clone, Debug)]
pub(crate) struct ExecutableMetadata {
    pub format: &'static str,
    pub architecture: String,
    pub available_architectures: Vec<String>,
    pub extra: ExecutableExtra,
}

/// Variant-specific facts carried alongside the common identity.
#[derive(Clone, Debug)]
pub(crate) enum ExecutableExtra {
    /// mach-o / elf (non-family) / dos-mz / dos-com: no extra metadata keys.
    None,
    /// ELF family metadata under `mips` / `riscv` / `powerpc`.
    ElfFamily { key: &'static str, value: Value },
    /// Universal Mach-O slice.
    UniversalSlice { offset: u64, size: u64 },
    /// PE facts: peMachine, executableRole, managed, optional codeView.
    Pe {
        pe_machine: u32,
        executable_role: &'static str,
        managed: bool,
        code_view: Option<Value>,
    },
}

impl ExecutableMetadata {
    /// Insert the variant metadata keys in TS object-literal order into the
    /// target `metadata` map (the caller has already inserted identity keys).
    pub fn insert_metadata(&self, metadata: &mut Map<String, Value>) {
        match &self.extra {
            ExecutableExtra::None => {}
            ExecutableExtra::ElfFamily { key, value } => {
                metadata.insert((*key).to_string(), value.clone());
            }
            ExecutableExtra::UniversalSlice { offset, size } => {
                metadata.insert(
                    "universalSlice".to_string(),
                    json!({ "offset": offset, "size": size }),
                );
            }
            ExecutableExtra::Pe {
                pe_machine,
                executable_role,
                managed,
                code_view,
            } => {
                metadata.insert("peMachine".to_string(), json!(pe_machine));
                metadata.insert("executableRole".to_string(), json!(*executable_role));
                metadata.insert("managed".to_string(), json!(*managed));
                if let Some(code_view) = code_view {
                    metadata.insert("codeView".to_string(), code_view.clone());
                }
            }
        }
    }
}

/// Little- or big-endian unsigned reads over a byte slice. Out-of-range reads
/// return 0, matching Node `Buffer.readUInt*` after bounds were established by
/// the caller's length checks.
pub(crate) fn read_u16(bytes: &[u8], offset: usize, little: bool) -> u16 {
    if offset + 2 > bytes.len() {
        return 0;
    }
    let value = [bytes[offset], bytes[offset + 1]];
    if little {
        u16::from_le_bytes(value)
    } else {
        u16::from_be_bytes(value)
    }
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize, little: bool) -> u32 {
    if offset + 4 > bytes.len() {
        return 0;
    }
    let value = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    if little {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    }
}

pub(crate) fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    read_u16(bytes, offset, true)
}

pub(crate) fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    read_u32(bytes, offset, true)
}

pub(crate) fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    read_u32(bytes, offset, false)
}

/// TS `parseExecutableHeader(bytes, hostArchitecture, fileSize, mzSig?)`.
///
/// `host_architecture` is a Node `process.arch` name for FAT slice selection.
pub(crate) fn parse_executable_header(
    bytes: &[u8],
    host_architecture: &str,
    file_size: u64,
    mz_windows_header_signature: Option<&[u8]>,
) -> Result<ExecutableMetadata, String> {
    if bytes.len() >= 4 && bytes[0..4] == [0x7f, 0x45, 0x4c, 0x46] {
        return elf::parse_elf(bytes, file_size);
    }
    if bytes.len() >= 2 && bytes[0] == 0x4d && bytes[1] == 0x5a {
        return pe::parse_mz(bytes, file_size, mz_windows_header_signature);
    }
    if bytes.len() < 8 {
        return Err("truncated or unsupported binary header".to_string());
    }
    let magic = read_u32_be(bytes, 0);
    if matches!(magic, 0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe) {
        return macho::parse_thin_macho(bytes, magic, file_size);
    }
    macho::parse_fat_or_unsupported(bytes, host_architecture, file_size)
}
