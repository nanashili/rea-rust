//! Fixed ELF header architecture naming for the fuse reader.
//!
//! Compatibility owner: `src/domain/elfFixedHeader.ts` (`readElfFixedHeader`,
//! `elfArchitecture`). The fuse reader consumes only the architecture; it is
//! `None` whenever the fixed header does not validate.

/// Architecture name from a validated fixed ELF header, or `None`.
pub fn elf_architecture(bytes: &[u8], total_bytes: usize) -> Option<String> {
    read_fixed_header(bytes, total_bytes).map(str::to_owned)
}

fn read_fixed_header(bytes: &[u8], total_bytes: usize) -> Option<&'static str> {
    if bytes.len() >= 4 && &bytes[..4] != b"\x7fELF" {
        return None;
    }
    if bytes.len() < 16 {
        return None;
    }
    let class_byte = bytes[4];
    if class_byte != 1 && class_byte != 2 {
        return None;
    }
    let data_byte = bytes[5];
    if data_byte != 1 && data_byte != 2 {
        return None;
    }
    if bytes[6] != 1 {
        return None;
    }
    let elf_class = if class_byte == 1 { 32 } else { 64 };
    let minimum_size = if elf_class == 32 { 52 } else { 64 };
    if total_bytes < bytes.len() || total_bytes < minimum_size || bytes.len() < minimum_size {
        return None;
    }
    let little_endian = data_byte == 1;
    let read_u16 = |offset: usize| -> u16 {
        let raw = [bytes[offset], bytes[offset + 1]];
        if little_endian {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        }
    };
    let read_u32 = |offset: usize| -> u32 {
        let raw = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ];
        if little_endian {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        }
    };
    if read_u32(20) != 1 {
        return None;
    }
    let header_size = read_u16(if elf_class == 32 { 40 } else { 52 }) as usize;
    if header_size < minimum_size || header_size > total_bytes {
        return None;
    }
    let machine = read_u16(18);
    elf_machine_architecture(machine)
}

fn elf_machine_architecture(machine: u16) -> Option<&'static str> {
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
