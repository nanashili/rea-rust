//! Bounded ELF64 core-file observations for the supported Linux note profiles.
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Report {
    pub format: &'static str,
    pub architecture: &'static str,
    pub segments: Vec<Segment>,
    pub notes: Vec<Note>,
    pub threads: Vec<Thread>,
    pub signals: Vec<Signal>,
    pub limitations: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct Segment {
    pub index: usize,
    pub offset: String,
    pub file_size: String,
    pub memory_size: String,
    pub virtual_address: String,
    pub flags: String,
    pub file_backing: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Note {
    pub index: usize,
    pub segment_index: usize,
    pub note_type: u32,
    pub owner_bytes_base64: String,
    pub descriptor_bytes_base64: String,
    pub owner_offset: usize,
    pub descriptor_offset: usize,
}
#[derive(Debug, Serialize)]
pub struct Thread {
    pub note_index: usize,
    pub historical_pid: i32,
    pub recorded_current_signal: i16,
    pub registers: Vec<Register>,
}
#[derive(Debug, Serialize)]
pub struct Register {
    pub name: &'static str,
    pub value: String,
    pub offset: usize,
}
#[derive(Debug, Serialize)]
pub struct Signal {
    pub note_index: usize,
    pub number: i32,
    pub code: i32,
    pub errno: i32,
    pub fault_address: Option<String>,
}

pub fn inspect(bytes: &[u8]) -> Result<Report, String> {
    if bytes.len() < 64
        || &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || !matches!(u16le(bytes, 18), 62 | 183)
    {
        return Err("Expected an ELF64 little-endian amd64 or AArch64 core file.".into());
    }
    let architecture = if u16le(bytes, 18) == 62 {
        "x86_64-little-endian"
    } else {
        "aarch64-little-endian"
    };
    let phoff = u64le(bytes, 32) as usize;
    let phentsize = u16le(bytes, 54) as usize;
    let phnum = u16le(bytes, 56) as usize;
    if phentsize < 56
        || phnum > 4096
        || phoff
            .checked_add(
                phentsize
                    .checked_mul(phnum)
                    .ok_or("program header overflow")?,
            )
            .ok_or("program header overflow")?
            > bytes.len()
    {
        return Err("ELF program headers exceed the artifact.".into());
    }
    let mut segments = Vec::new();
    let mut notes = Vec::new();
    let mut threads = Vec::new();
    let mut signals = Vec::new();
    let aarch64 = architecture == "aarch64-little-endian";

    for index in 0..phnum {
        let at = phoff + index * phentsize;
        let kind = u32le(bytes, at);
        let offset = u64le(bytes, at + 8) as usize;
        let size = u64le(bytes, at + 32) as usize;
        if offset.checked_add(size).ok_or("segment overflow")? > bytes.len() {
            return Err("ELF segment exceeds the artifact.".into());
        }
        if kind == 1 {
            segments.push(Segment {
                index,
                offset: hex(u64le(bytes, at + 8)),
                file_size: hex(u64le(bytes, at + 32)),
                memory_size: hex(u64le(bytes, at + 40)),
                virtual_address: hex(u64le(bytes, at + 16)),
                flags: hex(u64le(bytes, at + 4)),
                file_backing: if size == 0 { "none" } else { "file" },
            });
        }
        if kind == 4 {
            parse_notes(
                bytes,
                offset,
                size,
                index,
                aarch64,
                &mut notes,
                &mut threads,
                &mut signals,
            );
        }
    }
    Ok(Report { format: "elf-core", architecture, segments, notes, threads, signals, limitations: vec!["Historical process identity, current file identity, note coverage and signal-thread association remain unknown.".into(), "Debugger mapping candidates are intentionally not requested by this offline parser.".into()] })
}

fn parse_notes(
    bytes: &[u8],
    start: usize,
    size: usize,
    segment: usize,
    aarch64: bool,
    notes: &mut Vec<Note>,
    threads: &mut Vec<Thread>,
    signals: &mut Vec<Signal>,
) {
    let end = start + size;
    let mut at = start;
    while at + 12 <= end {
        let namesz = u32le(bytes, at) as usize;
        let descsz = u32le(bytes, at + 4) as usize;
        let kind = u32le(bytes, at + 8);
        let name_at = at + 12;
        let desc_at = (name_at + align4(namesz)).min(end);
        let next = desc_at.saturating_add(descsz);
        if next > end {
            break;
        }
        let owner_end = name_at
            .checked_add(namesz.min(end.saturating_sub(name_at)))
            .unwrap_or(end)
            .min(end);
        let owner = &bytes[name_at.min(end)..owner_end];
        let desc = &bytes[desc_at..next];
        let note_index = notes.len();
        notes.push(Note {
            index: note_index,
            segment_index: segment,
            note_type: kind,
            owner_bytes_base64: b64(owner),
            descriptor_bytes_base64: b64(desc),
            owner_offset: name_at,
            descriptor_offset: desc_at,
        });
        if owner == b"CORE\0" && kind == 1 && desc.len() >= 124 {
            threads.push(Thread {
                note_index,
                historical_pid: i32le(desc, 32),
                recorded_current_signal: i16le(desc, 12),
                registers: registers(desc, desc_at, aarch64),
            });
        }
        if owner == b"CORE\0" && kind == 0x53494749 && desc.len() >= 128 {
            signals.push(Signal {
                note_index,
                number: i32le(desc, 0),
                code: i32le(desc, 8),
                errno: i32le(desc, 4),
                fault_address: Some(hex(u64le(desc, 16))),
            });
        }
        at = next.saturating_add((4 - next % 4) % 4);
    }
}
fn registers(desc: &[u8], base: usize, aarch64: bool) -> Vec<Register> {
    const N: [&str; 27] = [
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx",
        "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds",
        "es", "fs", "gs",
    ];
    const AARCH64: [&str; 34] = [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
        "x27", "x28", "x29", "x30", "sp", "pc", "pstate",
    ];
    let names: &[&str] = if aarch64 { &AARCH64 } else { &N };
    names
        .iter()
        .enumerate()
        .filter_map(|(i, name)| {
            let at = 112 + i * 8;
            (at + 8 <= desc.len()).then(|| Register {
                name,
                value: hex(u64le(desc, at)),
                offset: base + at,
            })
        })
        .collect()
}
fn align4(value: usize) -> usize {
    (value + 3) & !3
}
fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn i16le(b: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([b[at], b[at + 1]])
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn i32le(b: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn hex(value: u64) -> String {
    format!("0x{value:x}")
}
fn b64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0] as u32;
        let b = chunk.get(1).copied().unwrap_or(0) as u32;
        let c = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (a << 16) | (b << 8) | c;
        out.push(TABLE[(value >> 18) as usize] as char);
        out.push(TABLE[((value >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_header(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0; 64];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[16..18].copy_from_slice(&4u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes
    }

    #[test]
    fn rejects_non_elf() {
        assert!(inspect(b"MZ").is_err());
    }

    #[test]
    fn accepts_amd64_core_header_without_segments() {
        let report = inspect(&elf_header(62)).expect("amd64 ELF header should parse");
        assert_eq!(report.architecture, "x86_64-little-endian");
        assert!(report.segments.is_empty());
    }

    #[test]
    fn accepts_aarch64_core_header_without_segments() {
        let report = inspect(&elf_header(183)).expect("AArch64 ELF header should parse");
        assert_eq!(report.architecture, "aarch64-little-endian");
        assert!(report.segments.is_empty());
    }

    #[test]
    fn rejects_program_header_outside_artifact() {
        let mut bytes = elf_header(62);
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        assert!(inspect(&bytes).is_err());
    }
}
