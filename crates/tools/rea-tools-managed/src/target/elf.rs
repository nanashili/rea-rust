//! ELF fixed-header validation and family classification.
//!
//! Ports `src/domain/elfFixedHeader.ts` (`readElfFixedHeader`) and the ELF
//! branch of `src/domain/binaryTarget.ts` (`parseElf`).

use serde_json::json;

use super::header::{ExecutableExtra, ExecutableMetadata, read_u16, read_u32};

/// Validated fixed ELF header facts.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ElfFixedHeader {
    pub elf_class: u8, // 32 or 64
    pub little_endian: bool,
    pub header_size: u16,
    pub machine: u16,
    /// Family name or None when the machine is unsupported.
    pub architecture: Option<&'static str>,
}

/// TS `readElfFixedHeader(bytes, totalBytes)`.
pub(crate) fn read_elf_fixed_header(
    bytes: &[u8],
    total_bytes: u64,
) -> Result<ElfFixedHeader, String> {
    if bytes.len() >= 4 && &bytes[0..4] != [0x7f, 0x45, 0x4c, 0x46].as_slice() {
        return Err("not an ELF image".to_string());
    }
    if bytes.len() < 16 {
        return Err("ELF identification is truncated".to_string());
    }
    let class_byte = bytes[4];
    if class_byte != 1 && class_byte != 2 {
        return Err("unsupported ELF class".to_string());
    }
    let data_byte = bytes[5];
    if data_byte != 1 && data_byte != 2 {
        return Err("unsupported ELF endianness".to_string());
    }
    if bytes[6] != 1 {
        return Err("unsupported ELF identification version".to_string());
    }
    let elf_class: u8 = if class_byte == 1 { 32 } else { 64 };
    let minimum_size: u64 = if elf_class == 32 { 52 } else { 64 };
    if total_bytes < bytes.len() as u64
        || total_bytes < minimum_size
        || (bytes.len() as u64) < minimum_size
    {
        return Err(format!(
            "truncated ELF header: an ELF{elf_class} header needs {minimum_size} bytes; the file has {total_bytes}"
        ));
    }
    let little = data_byte == 1;
    if read_u32(bytes, 20, little) != 1 {
        return Err("unsupported ELF header version".to_string());
    }
    let header_size = read_u16(bytes, if elf_class == 32 { 40 } else { 52 }, little);
    if (header_size as u64) < minimum_size || (header_size as u64) > total_bytes {
        return Err("invalid ELF header size".to_string());
    }
    let machine = read_u16(bytes, 18, little);
    Ok(ElfFixedHeader {
        elf_class,
        little_endian: little,
        header_size,
        machine,
        architecture: elf_architecture(machine),
    })
}

fn elf_architecture(machine: u16) -> Option<&'static str> {
    match machine {
        3 => Some("x86"),
        62 => Some("x86_64"),
        8 => Some("mips"),
        20 => Some("powerpc"),
        40 => Some("arm"),
        164 => Some("hexagon"),
        183 => Some("arm64"),
        243 => Some("riscv"),
        _ => None,
    }
}

/// TS `parseElf(bytes, fileSize)`.
pub(crate) fn parse_elf(bytes: &[u8], file_size: u64) -> Result<ExecutableMetadata, String> {
    let fixed = read_elf_fixed_header(bytes, file_size)?;
    let little = fixed.little_endian;
    let architecture = match fixed.architecture {
        Some(architecture) => architecture,
        None => return Err("unsupported ELF architecture".to_string()),
    };

    if architecture == "mips" || architecture == "riscv" || architecture == "powerpc" {
        let flags_offset = if fixed.elf_class == 32 { 36 } else { 48 };
        // ElfFamilyMetadata: elfClass, byteOrder, type, flags (in that order).
        let family = json!({
            "elfClass": fixed.elf_class,
            "byteOrder": if little { "little" } else { "big" },
            "type": read_u16(bytes, 16, little),
            "flags": read_u32(bytes, flags_offset, little),
        });
        let key = match architecture {
            "mips" => "mips",
            "riscv" => "riscv",
            _ => "powerpc",
        };
        return Ok(ExecutableMetadata {
            format: "elf",
            architecture: architecture.to_string(),
            available_architectures: vec![architecture.to_string()],
            extra: ExecutableExtra::ElfFamily { key, value: family },
        });
    }

    // hexagon and all other recognized families: header alone is the fact.
    Ok(ExecutableMetadata {
        format: "elf",
        architecture: architecture.to_string(),
        available_architectures: vec![architecture.to_string()],
        extra: ExecutableExtra::None,
    })
}
