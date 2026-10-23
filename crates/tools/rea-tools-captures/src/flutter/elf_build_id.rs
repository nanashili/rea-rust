//! GNU build-id recovery from ELF-declared note ranges.
//!
//! Compatibility owner: `src/flutter/ElfBuildId.ts`. The TypeScript reader
//! performs positional reads against an owned engine file handle; this port
//! reads from the fully buffered engine image instead, preserving the same
//! budgets, range inventory and failure classification.

use std::collections::HashSet;

use crate::flutter::dart_elf::{ELF_HEADER_MAX_BYTES, read_elf_header};

const MAX_METADATA_BYTES: u64 = 8 * 1024 * 1024;
const MAX_BUILD_IDS: usize = 64;
const MAX_NOTE_RANGES: usize = 1024;

pub struct ElfBuildIds {
    pub candidates: Vec<String>,
    pub failures: Vec<String>,
}

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn is_safe_integer(value: u64) -> bool {
    value <= MAX_SAFE_INTEGER
}

/// Read only ELF-declared PT_NOTE/SHT_NOTE ranges from one engine image.
pub fn read_elf_build_ids(image: &[u8], total_bytes: usize) -> ElfBuildIds {
    let total = total_bytes as u64;
    let mut candidates: Vec<String> = Vec::new();
    let mut candidate_set: HashSet<String> = HashSet::new();
    let mut failures: Vec<String> = Vec::new();
    let mut examined: u64 = 0;

    // `read(offset, size)` in TS performs bounds and budget checks, then copies
    // from the file; here it slices the buffered image under the same rules.
    let read = |offset: u64, size: u64, examined: &mut u64| -> Option<Vec<u8>> {
        if !is_safe_integer(offset)
            || !is_safe_integer(size)
            || size > total.saturating_sub(offset)
            || offset > total
            || size > MAX_METADATA_BYTES.saturating_sub(*examined)
        {
            return None;
        }
        *examined += size;
        let start = offset as usize;
        let end = start + size as usize;
        image.get(start..end).map(<[u8]>::to_vec)
    };

    let prefix = match read(0, total.min(ELF_HEADER_MAX_BYTES as u64), &mut examined) {
        Some(prefix) => prefix,
        None => {
            failures.push("ELF header could not be read".into());
            return ElfBuildIds {
                candidates,
                failures,
            };
        }
    };
    let header = match read_elf_header(&prefix, total_bytes) {
        Ok(header) => header,
        Err(reason) => {
            failures.push(reason);
            return ElfBuildIds {
                candidates,
                failures,
            };
        }
    };

    struct TableSpec {
        offset: u64,
        width: u64,
        count: u64,
        program: bool,
    }
    let table_specs = [
        TableSpec {
            offset: header.e_phoff,
            width: u64::from(header.e_phentsize),
            count: u64::from(header.e_phnum),
            program: true,
        },
        TableSpec {
            offset: header.e_shoff,
            width: u64::from(header.e_shentsize),
            count: u64::from(header.e_shnum),
            program: false,
        },
    ];

    // Insertion-ordered unique ranges keyed by `offset:size`.
    let mut range_keys: HashSet<(u64, u64)> = HashSet::new();
    let mut ranges: Vec<(u64, u64)> = Vec::new();

    'tables: for table in table_specs {
        let bytes = match read(table.offset, table.width * table.count, &mut examined) {
            Some(bytes) => bytes,
            None => {
                failures.push(
                    "ELF note tables exceed the 8 MiB metadata budget or are truncated".into(),
                );
                return ElfBuildIds {
                    candidates,
                    failures,
                };
            }
        };
        for index in 0..table.count {
            let base = (index * table.width) as usize;
            let type_at = base + if table.program { 0 } else { 4 };
            let note_type = read_u32_le(&bytes, type_at);
            let expected = if table.program { 4 } else { 7 };
            if note_type != Some(expected) {
                continue;
            }
            let offset_at = base
                + if table.program {
                    if header.is64 { 8 } else { 4 }
                } else if header.is64 {
                    0x18
                } else {
                    0x10
                };
            let size_at = base
                + if table.program {
                    if header.is64 { 0x20 } else { 0x10 }
                } else if header.is64 {
                    0x20
                } else {
                    0x14
                };
            let (offset, size) = if header.is64 {
                (read_u64_le(&bytes, offset_at), read_u64_le(&bytes, size_at))
            } else {
                (
                    read_u32_le(&bytes, offset_at).map(u64::from),
                    read_u32_le(&bytes, size_at).map(u64::from),
                )
            };
            let (offset, size) = match (offset, size) {
                (Some(offset), Some(size)) => (offset, size),
                _ => {
                    failures.push("ELF note range is not file-backed".into());
                    return ElfBuildIds {
                        candidates,
                        failures,
                    };
                }
            };
            if !is_safe_integer(offset)
                || !is_safe_integer(size)
                || size > total.saturating_sub(offset)
            {
                failures.push("ELF note range is not file-backed".into());
                return ElfBuildIds {
                    candidates,
                    failures,
                };
            }
            if size == 0 {
                continue;
            }
            let key = (offset, size);
            if range_keys.contains(&key) {
                continue;
            }
            if ranges.len() == MAX_NOTE_RANGES {
                failures.push(
                    "ELF notes exceed the 1024-range note-range inventory/read budget".into(),
                );
                break 'tables;
            }
            range_keys.insert(key);
            ranges.push(key);
        }
    }

    for (offset, size) in ranges {
        let notes = match read(offset, size, &mut examined) {
            Some(notes) => notes,
            None => {
                failures.push("ELF notes exceed the 8 MiB metadata budget or are truncated".into());
                return ElfBuildIds {
                    candidates,
                    failures,
                };
            }
        };
        let mut at = 0usize;
        while at < notes.len() {
            if notes.len() - at < 12 {
                if notes[at..].iter().any(|&byte| byte != 0) {
                    failures.push("ELF note header is truncated".into());
                    return ElfBuildIds {
                        candidates,
                        failures,
                    };
                }
                break;
            }
            let namesz = read_u32_le(&notes, at).unwrap_or(0) as usize;
            let descsz = read_u32_le(&notes, at + 4).unwrap_or(0) as usize;
            let note_type = read_u32_le(&notes, at + 8).unwrap_or(0);
            let descriptor = at + 12 + align4(namesz);
            let end = descriptor + descsz;
            if end > notes.len() {
                failures.push("ELF note descriptor exceeds its declared note range".into());
                return ElfBuildIds {
                    candidates,
                    failures,
                };
            }
            if namesz == 4
                && note_type == 3
                && notes.get(at + 12..at + 16) == Some(b"GNU\0".as_slice())
            {
                if descsz < 4 || descsz > 64 {
                    failures
                        .push("GNU build-id descriptor exceeds the 4–64 byte projection".into());
                    return ElfBuildIds {
                        candidates,
                        failures,
                    };
                }
                let candidate = hex(&notes[descriptor..end]);
                if !candidate_set.contains(&candidate) && candidate_set.len() == MAX_BUILD_IDS {
                    failures
                        .push("ELF build-id candidates exceed the 64-value evidence budget".into());
                    return ElfBuildIds {
                        candidates,
                        failures,
                    };
                }
                if candidate_set.insert(candidate.clone()) {
                    candidates.push(candidate);
                }
            }
            at = align4(end);
        }
    }

    ElfBuildIds {
        candidates,
        failures,
    }
}

fn align4(value: usize) -> usize {
    value.div_ceil(4) * 4
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|slice| {
        u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ])
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}
