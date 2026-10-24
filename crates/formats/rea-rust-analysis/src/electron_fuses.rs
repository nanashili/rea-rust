//! Bounded, artifact-only Electron fuse wire decoding.

use serde::Serialize;

pub const SENTINEL: &[u8] = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";
pub const MAX_SENTINELS_PER_SLICE: usize = 32;

#[derive(Debug, Serialize, Clone)]
pub struct Fuse {
    pub index: usize,
    pub name: Option<&'static str>,
    pub state: &'static str,
    pub raw_byte: u8,
}

#[derive(Debug, Serialize, Clone)]
pub struct Sentinel {
    pub sentinel_offset: usize,
    pub wire_version: Option<u8>,
    pub declared_length: Option<u8>,
    pub fuses: Vec<Fuse>,
    pub complete: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct Slice {
    pub index: usize,
    pub file_offset: usize,
    pub size: usize,
    pub architecture: Option<String>,
    pub sentinel_count: usize,
    pub sentinels: Vec<Sentinel>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Implication {
    pub relationship: &'static str,
    pub slice_index: usize,
    pub sentinel_offset: usize,
    pub subject: &'static str,
    pub fuse_index: usize,
    pub outcome: &'static str,
}

#[derive(Debug, Serialize, Clone)]
pub struct Report {
    pub artifact: Artifact,
    pub slices: Vec<Slice>,
    pub runtime_implications: Vec<Implication>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Artifact {
    pub sha256: String,
    pub bytes: usize,
    pub format: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct Range {
    offset: usize,
    size: usize,
    architecture: Option<&'static str>,
}

pub fn inspect(bytes: &[u8], sha256: String) -> Result<Report, String> {
    let (format, ranges) = identify_ranges(bytes)?;
    let mut slices = Vec::with_capacity(ranges.len());
    for (index, range) in ranges.into_iter().enumerate() {
        let slice_bytes = &bytes[range.offset..range.offset + range.size];
        let sentinels = scan_slice(slice_bytes, range.offset)?;
        slices.push(Slice {
            index,
            file_offset: range.offset,
            size: range.size,
            architecture: range.architecture.map(str::to_owned),
            sentinel_count: sentinels.len(),
            sentinels,
        });
    }

    let mut report = Report {
        artifact: Artifact { sha256, bytes: bytes.len(), format },
        slices,
        runtime_implications: Vec::new(),
        limitations: vec![
            "Fuse state does not prove the application enables Inspector through other means, such as app.commandLine or a remote-debugging switch in application code.".into(),
            "A missing sentinel means fuse state is unknown, not that every fuse is disabled.".into(),
        ],
    };
    derive_findings(&mut report);
    Ok(report)
}

fn identify_ranges(bytes: &[u8]) -> Result<(&'static str, Vec<Range>), String> {
    if bytes.len() >= 4 && is_macho_magic(&bytes[..4]) {
        if let Some(ranges) = fat_macho_ranges(bytes) {
            return Ok(("mach-o-universal", ranges));
        }
        return Ok((
            "mach-o",
            vec![Range {
                offset: 0,
                size: bytes.len(),
                architecture: macho_architecture(bytes),
            }],
        ));
    }
    if bytes.starts_with(b"\x7fELF") {
        return Ok((
            "elf",
            vec![Range {
                offset: 0,
                size: bytes.len(),
                architecture: elf_architecture(bytes),
            }],
        ));
    }
    if bytes.starts_with(b"MZ") {
        return Ok((
            "pe",
            vec![Range {
                offset: 0,
                size: bytes.len(),
                architecture: pe_architecture(bytes),
            }],
        ));
    }
    Err("Selected artifact is not a supported Mach-O, PE, or ELF image.".into())
}

fn scan_slice(bytes: &[u8], base: usize) -> Result<Vec<Sentinel>, String> {
    let mut result = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = find_bytes(&bytes[cursor..], SENTINEL) {
        if result.len() == MAX_SENTINELS_PER_SLICE {
            return Err("Electron fuse sentinel capacity exceeded.".into());
        }
        let start = cursor + relative;
        result.push(parse_wire(bytes, start, base + start));
        cursor = start + SENTINEL.len();
    }
    Ok(result)
}

fn parse_wire(bytes: &[u8], start: usize, absolute: usize) -> Sentinel {
    let version = bytes.get(start + SENTINEL.len()).copied();
    let declared = version.and_then(|_| bytes.get(start + SENTINEL.len() + 1).copied());
    let count = declared.unwrap_or(0) as usize;
    let fuse_start = start + SENTINEL.len() + 2;
    let available = bytes.len().saturating_sub(fuse_start).min(count);
    let fuses = (0..available)
        .map(|index| {
            let raw_byte = bytes[fuse_start + index];
            Fuse {
                index,
                name: version.and_then(|version| fuse_name(version, index)),
                state: fuse_state(raw_byte),
                raw_byte,
            }
        })
        .collect();
    Sentinel {
        sentinel_offset: absolute,
        wire_version: version,
        declared_length: declared,
        fuses,
        complete: declared.is_some_and(|length| available == length as usize),
    }
}

fn derive_findings(report: &mut Report) {
    for slice in &report.slices {
        if slice.sentinel_count == 0 {
            report.limitations.push(format!("Slice {} at file offset {} contains no Electron fuse sentinel; fuse state for that slice is unknown, not disabled.", slice.index, slice.file_offset));
        }
        for sentinel in &slice.sentinels {
            if !sentinel.complete {
                report.limitations.push(format!("Electron fuse wire at file offset {} is truncated; fuse bytes past the slice stay unknown.", sentinel.sentinel_offset));
            }
            if sentinel.wire_version != Some(1) {
                continue;
            }
            for (subject, index, enabled, inactive) in [
                ("node_cli_inspect_arguments", 3, "honored", "not_honored"),
                ("electron_run_as_node", 0, "honored", "not_honored"),
                (
                    "embedded_asar_integrity_validation",
                    4,
                    "enforced",
                    "not_enforced",
                ),
                (
                    "only_load_app_from_asar",
                    5,
                    "restricted_to_app_asar",
                    "not_restricted_to_app_asar",
                ),
            ] {
                let Some(fuse) = sentinel.fuses.iter().find(|fuse| fuse.index == index) else {
                    continue;
                };
                let outcome = if fuse.state == "enabled" {
                    enabled
                } else if fuse.state == "unknown" {
                    "unknown"
                } else {
                    inactive
                };
                report.runtime_implications.push(Implication {
                    relationship: "derivation",
                    slice_index: slice.index,
                    sentinel_offset: sentinel.sentinel_offset,
                    subject,
                    fuse_index: index,
                    outcome,
                });
            }
        }
    }
}

fn fuse_name(version: u8, index: usize) -> Option<&'static str> {
    if version != 1 {
        return None;
    }
    [
        "RunAsNode",
        "EnableCookieEncryption",
        "EnableNodeOptionsEnvironmentVariable",
        "EnableNodeCliInspectArguments",
        "EnableEmbeddedAsarIntegrityValidation",
        "OnlyLoadAppFromAsar",
        "LoadBrowserProcessSpecificV8Snapshot",
        "GrantFileProtocolExtraPrivileges",
        "WasmTrapHandlers",
    ]
    .get(index)
    .copied()
}

fn fuse_state(byte: u8) -> &'static str {
    match byte {
        0x30 => "disabled",
        0x31 => "enabled",
        0x72 => "removed",
        _ => "unknown",
    }
}
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(haystack, needle)
}
fn is_macho_magic(bytes: &[u8]) -> bool {
    matches!(
        u32::from_be_bytes(bytes.try_into().unwrap()),
        0xfeedface
            | 0xfeedfacf
            | 0xcefaedfe
            | 0xcffaedfe
            | 0xcafebabe
            | 0xcafebabf
            | 0xbebafeca
            | 0xbfbafeca
    )
}
fn fat_macho_ranges(bytes: &[u8]) -> Option<Vec<Range>> {
    let magic = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?);
    if !matches!(magic, 0xcafebabe | 0xcafebabf | 0xbebafeca | 0xbfbafeca) {
        return None;
    }
    let little = matches!(magic, 0xbebafeca | 0xbfbafeca);
    let read = |offset: usize| -> Option<u32> {
        let raw = bytes.get(offset..offset + 4)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    };
    let count = read(4)? as usize;
    let descriptor = if magic == 0xcafebabf || magic == 0xbfbafeca {
        32
    } else {
        20
    };
    let mut ranges = Vec::new();
    for index in 0..count {
        let base = 8 + index * descriptor;
        let offset = read(base + 8)? as usize;
        let size = read(base + 16)? as usize;
        if offset.checked_add(size)? > bytes.len() {
            return None;
        }
        ranges.push(Range {
            offset,
            size,
            architecture: None,
        });
    }
    Some(ranges)
}
fn macho_architecture(bytes: &[u8]) -> Option<&'static str> {
    match u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) {
        0xfeedface | 0xcefaedfe => Some("x86"),
        0xfeedfacf | 0xcffaedfe => Some("x86_64"),
        _ => None,
    }
}
fn elf_architecture(bytes: &[u8]) -> Option<&'static str> {
    match u16::from_le_bytes(bytes.get(18..20)?.try_into().ok()?) {
        3 => Some("x86"),
        62 => Some("x86_64"),
        40 => Some("arm"),
        183 => Some("arm64"),
        _ => None,
    }
}
fn pe_architecture(bytes: &[u8]) -> Option<&'static str> {
    let offset = u32::from_le_bytes(bytes.get(0x3c..0x40)?.try_into().ok()?) as usize;
    match u16::from_le_bytes(bytes.get(offset + 4..offset + 6)?.try_into().ok()?) {
        0x14c => Some("x86"),
        0x8664 => Some("x86_64"),
        0xaa64 => Some("arm64"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_version_one_wire_and_derives_implications() {
        let mut bytes = b"\x7fELF".to_vec();
        bytes.extend_from_slice(SENTINEL);
        bytes.extend([1, 6, 0x31, 0x30, 0x72, 0x31, 0x31, 0x30]);
        let report = inspect(&bytes, "a".repeat(64)).unwrap();
        assert_eq!(
            report.slices[0].sentinels[0].fuses[3].name,
            Some("EnableNodeCliInspectArguments")
        );
        assert_eq!(report.slices[0].sentinels[0].fuses[2].state, "removed");
        assert_eq!(report.runtime_implications[0].outcome, "honored");
    }

    #[test]
    fn preserves_unknown_wire_and_missing_sentinel() {
        let report = inspect(b"\x7fELF", "b".repeat(64)).unwrap();
        assert!(report.slices[0].sentinels.is_empty());
        assert!(
            report
                .limitations
                .iter()
                .any(|item| item.contains("unknown, not disabled"))
        );
    }

    #[test]
    fn scans_multiple_wires_with_offsets_and_enforces_capacity() {
        let mut bytes = b"\x7fELF".to_vec();
        for _ in 0..MAX_SENTINELS_PER_SLICE {
            bytes.extend_from_slice(SENTINEL);
            bytes.extend_from_slice(&[1, 1, b'1']);
        }
        let report = inspect(&bytes, String::new()).unwrap();
        let sentinels = &report.slices[0].sentinels;
        assert_eq!(sentinels.len(), MAX_SENTINELS_PER_SLICE);
        assert_eq!(
            sentinels.last().unwrap().sentinel_offset,
            4 + (MAX_SENTINELS_PER_SLICE - 1) * (SENTINEL.len() + 3)
        );
        assert!(sentinels.iter().all(|wire| wire.complete));
        bytes.extend_from_slice(SENTINEL);
        assert!(
            inspect(&bytes, String::new())
                .unwrap_err()
                .contains("capacity")
        );
    }
}
