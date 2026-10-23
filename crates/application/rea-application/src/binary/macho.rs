//! Application boundary for read-only Mach-O Evidence.

use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use rea_core::{
    evidence::{
        Architecture, ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
    },
    failure::{Detail, Failure},
    json_output,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::{image, macho};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "inspect_macho";
const PROVIDER: Provider = Provider {
    id: "rust-macho",
    name: "REA Rust Mach-O reader",
    version: Some("1"),
};
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
pub struct MachoAnalyzer;

impl ArtifactAnalyzer for MachoAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = image::MAX_INPUT_BYTES;

    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(path, snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn projects_note_source_and_payload_ranges_into_evidence_locations() {
        let header = 32;
        let command = 40;
        let payload = header + command;
        let mut bytes = vec![0u8; payload + 4];
        put32(&mut bytes, 0, 0xfeedfacf);
        put32(&mut bytes, 4, 0x0100000c);
        put32(&mut bytes, 16, 1);
        put32(&mut bytes, 20, command as u32);
        put32(&mut bytes, header, 0x31);
        put32(&mut bytes, header + 4, command as u32);
        bytes[header + 8..header + 12].copy_from_slice(b"TEST");
        put64(&mut bytes, header + 24, payload as u64);
        put64(&mut bytes, header + 32, 4);
        bytes[payload..payload + 4].copy_from_slice(b"data");

        let image = macho::read(&bytes).expect("valid note image");
        let locations = locations_for("fixture", &image).expect("locations are bounded");
        assert!(locations.iter().any(|location| matches!(
            location,
            Location::FileOffsetRange { start, end }
                if *start == header as u64 && *end == (header + command) as u64
        )));
        assert!(locations.iter().any(|location| matches!(
            location,
            Location::FileOffsetRange { start, end }
                if *start == payload as u64 && *end == (payload + 4) as u64
        )));
        assert_eq!(image.notes[0].owner, "TEST");
        assert_eq!(image.notes[0].source_offset, header as u64);
        assert_eq!(image.notes[0].offset, payload as u64);
    }

    #[test]
    fn projects_function_starts_command_table_and_entry_ranges() {
        let header = 32;
        let segment = 72;
        let function_starts = 16;
        let payload = header + segment + function_starts;
        let mut bytes = vec![0u8; payload + 3];
        put32(&mut bytes, 0, 0xfeedfacf);
        put32(&mut bytes, 4, 0x0100000c);
        put32(&mut bytes, 12, 2);
        put32(&mut bytes, 16, 2);
        put32(&mut bytes, 20, (segment + function_starts) as u32);
        put32(&mut bytes, header, 0x19);
        put32(&mut bytes, header + 4, segment as u32);
        bytes[header + 8..header + 14].copy_from_slice(b"__TEXT");
        put64(&mut bytes, header + 24, 0x100000000);
        put64(&mut bytes, header + 32, 0x1000);
        put64(&mut bytes, header + 40, 0);
        let file_size = bytes.len() as u64;
        put64(&mut bytes, header + 48, file_size);
        put32(&mut bytes, header + 56, 5);
        put32(&mut bytes, header + 60, 5);
        put32(&mut bytes, header + segment, 0x26);
        put32(&mut bytes, header + segment + 4, function_starts as u32);
        put32(&mut bytes, header + segment + 8, payload as u32);
        put32(&mut bytes, header + segment + 12, 3);
        bytes[payload..].copy_from_slice(&[0x10, 0x20, 0]);

        let image = macho::read(&bytes).expect("valid function-starts image");
        let locations = locations_for("fixture", &image).expect("locations are bounded");
        assert!(locations.iter().any(|location| matches!(
            location,
            Location::FileOffsetRange { start, end }
                if *start == (header + segment) as u64
                    && *end == (header + segment + function_starts) as u64
        )));
        assert!(locations.iter().any(|location| matches!(
            location,
            Location::FileOffsetRange { start, end }
                if *start == payload as u64 && *end == (payload + 3) as u64
        )));
        assert!(locations.iter().any(|location| matches!(
            location,
            Location::FileOffsetRange { start, end }
                if *start == payload as u64 && *end == (payload + 1) as u64
        )));
    }
}

pub struct MachoInspection<F: rea_host::fs::stable_file::FileAccess> {
    inner: ArtifactInspection<F, MachoAnalyzer>,
}

impl<F: rea_host::fs::stable_file::FileAccess> MachoInspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            inner: ArtifactInspection::new(access),
        }
    }
    pub fn with_records(
        access: Arc<F>,
        records: Arc<crate::ledger::artifact_records::ArtifactRecords>,
    ) -> Self {
        Self {
            inner: ArtifactInspection::with_records(access, records),
        }
    }
    pub fn records(&self) -> &Arc<crate::ledger::artifact_records::ArtifactRecords> {
        self.inner.records()
    }
    pub fn close(&mut self) -> Result<(), Failure> {
        self.inner.close()
    }
    pub fn inspect(
        &mut self,
        path: &str,
        cancellation: &rea_core::cancellation::Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect(path, cancellation, completion)
    }
}

#[derive(Debug, Serialize)]
struct Artifact {
    path: String,
    sha256: String,
    bytes: usize,
}

#[derive(Debug, Serialize)]
struct Report {
    artifact: Artifact,
    #[serde(flatten)]
    macho: macho::Image,
    limitations: Vec<String>,
}

fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
    let parsed =
        macho::read(&snapshot.bytes).map_err(|error| execution(path, error.to_string()))?;
    let locations = locations_for(path, &parsed)?;
    let limitations = vec![
        "Mach-O facts are decoded from the stable byte snapshot without launching the target or invoking Apple tooling.".into(),
        "Imports and exports are sourced from LC_SYMTAB, dyld export/bind streams, and supported chained-fixup import tables. Bounded dyld rebase streams, LC_FUNCTION_STARTS entries, LC_DATA_IN_CODE records, and structural code-signature metadata are decoded. Code-signature facts do not validate trust or authenticity.".into(),
        "Encryption metadata preserves LC_ENCRYPTION_INFO command ranges, cryptid values, explicit encrypted or unencrypted state, and unknown state for invalid ranges; it does not decrypt bytes or verify protection.".into(),
        "LC_NOTE owner bytes and bounded file ranges are preserved as opaque metadata; note payloads are not interpreted.".into(),
        "LC_MAIN entry offsets are mapped to VM addresses only when a file-backed segment proves the mapping. Supported x86_64 and arm64 LC_UNIXTHREAD PC fields are decoded without execution; other thread states remain raw.".into(),
        "LC_FILESET_ENTRY metadata is decoded without recursively inspecting child images; entry IDs and bounded file offsets are preserved.".into(),
        "LC_BUILD_VERSION platform values are retained with minimum OS, SDK, and bounded tool-version records; enum values are not normalized away.".into(),
        "LC_RPATH and LC_DYLD_ENVIRONMENT strings retain raw bytes, decoded values, exact command and string source ranges, and explicit invalid state for unterminated or out-of-command strings.".into(),
        "LC_LOAD_DYLINKER and LC_ID_DYLINKER paths retain bounded raw bytes, decoded values, command offsets, and malformed string issues.".into(),
        "Dylib load, weak, reexport, and upward commands retain bounded names, timestamps, compatibility versions, and current versions.".into(),
        "LC_UUID retains the raw 16-byte UUID and bounded command provenance alongside its hexadecimal value.".into(),
        "Section metadata retains the raw alignment exponent, normalized alignment bytes, flags, reserved fields, and bounded segment-derived layout.".into(),
        "Section flags retain the raw value and recognized Mach-O type and attribute names.".into(),
        "Build metadata preserves raw platform codes and recognized platform names.".into(),
        "Segment permissions preserve decoded read/write/execute bits and the raw protection value.".into(),
        "Code-signature child slots and CodeDirectory hash metadata are structural facts only; signature verification is not performed.".into(),
        "LC_SYMTAB nlist entries retain raw type, section, description, value, bounded names, and source offsets; unresolved string indexes remain invalid facts.".into(),
        "LC_DYSYMTAB offsets and indirect entries retain raw values; only exact local and absolute sentinels receive special classifications.".into(),
        "LC_DYLD_CHAINED_FIXUPS metadata retains bounded command data and header-relative starts/imports/symbol offsets; pointer facts are emitted only for decoded formats.".into(),
        "Chained-fixup imports retain raw table entry ranges, library ordinals, weak flags, addends, and bounded symbol names; unsupported formats remain explicit.".into(),
        "LC_LINKER_OPTION strings retain bounded raw and decoded option records; truncated options remain invalid facts.".into(),
        "Universal Mach-O containers require an explicit architecture selection and are rejected until the caller supplies one.".into(),
    ];
    let report = Report {
        artifact: Artifact {
            path: path.to_owned(),
            sha256: snapshot.sha256.clone(),
            bytes: snapshot.bytes.len(),
        },
        macho: parsed,
        limitations: limitations.clone(),
    };
    admit_report_length(path, &report)?;
    let subject = Subject::new(
        path,
        snapshot.sha256,
        NativeFormat::MachO,
        architecture_for(report.macho.cpu),
    )
    .map_err(|error| execution(path, error.to_string()))?;
    let evidence = ArtifactEvidence::new(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result: report,
            limitations,
            locations,
        },
    )
    .map_err(|error| execution(path, error.to_string()))?;
    Ok(Arc::new(evidence))
}

fn architecture_for(cpu: u32) -> Option<Architecture> {
    match cpu {
        7 => Some(Architecture::X86),
        0x0100_0007 => Some(Architecture::X86_64),
        12 => Some(Architecture::Arm),
        0x0100_000c => Some(Architecture::Arm64),
        18 => Some(Architecture::Powerpc),
        0x0100_0012 => Some(Architecture::Powerpc),
        _ => None,
    }
}

fn locations_for(path: &str, image: &macho::Image) -> Result<Vec<Location>, Failure> {
    let mut locations = vec![Location::ArtifactPath {
        path: path.to_owned(),
    }];
    for segment in &image.segments {
        if segment.file_size == 0 || !segment.file_range_valid {
            continue;
        }
        let end = segment
            .file_offset
            .checked_add(segment.file_size)
            .ok_or_else(|| execution(path, "Mach-O segment range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: segment.file_offset,
            end,
        });
    }
    for section in &image.sections {
        if section.size == 0 || !section.file_range_valid {
            continue;
        }
        let end = (section.file_offset as u64)
            .checked_add(section.size)
            .ok_or_else(|| execution(path, "Mach-O section range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: section.file_offset as u64,
            end,
        });
    }
    for command in &image.load_commands {
        let end = command
            .source_offset
            .checked_add(command.source_size)
            .ok_or_else(|| execution(path, "Mach-O load-command range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: command.source_offset,
            end,
        });
    }
    for source_version in &image.source_versions {
        let end = source_version
            .source_offset
            .checked_add(source_version.source_size)
            .ok_or_else(|| execution(path, "Mach-O source-version range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: source_version.source_offset,
            end,
        });
    }
    for hints in &image.linker_optimization_hints {
        let end = hints
            .source_offset
            .checked_add(hints.source_size)
            .ok_or_else(|| execution(path, "Mach-O optimization-hints range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: hints.source_offset,
            end,
        });
        if !hints.valid || hints.size == 0 {
            continue;
        }
        let payload_end = hints.offset.checked_add(hints.size).ok_or_else(|| {
            execution(path, "Mach-O optimization-hints payload overflowed.".into())
        })?;
        locations.push(Location::FileOffsetRange {
            start: hints.offset,
            end: payload_end,
        });
    }
    for split_info in &image.segment_split_infos {
        let command_end = split_info
            .source_offset
            .checked_add(split_info.source_size)
            .ok_or_else(|| {
                execution(
                    path,
                    "Mach-O segment-split command range overflowed.".into(),
                )
            })?;
        locations.push(Location::FileOffsetRange {
            start: split_info.source_offset,
            end: command_end,
        });
        if !split_info.valid || split_info.size == 0 {
            continue;
        }
        let data_end = split_info
            .offset
            .checked_add(split_info.size)
            .ok_or_else(|| execution(path, "Mach-O segment-split data range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: split_info.offset,
            end: data_end,
        });
    }
    for trie in &image.dyld_exports_tries {
        let end = trie
            .source_offset
            .checked_add(trie.source_size)
            .ok_or_else(|| execution(path, "Mach-O export-trie range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: trie.source_offset,
            end,
        });
        if !trie.valid || trie.size == 0 {
            continue;
        }
        let payload_end = trie
            .offset
            .checked_add(trie.size)
            .ok_or_else(|| execution(path, "Mach-O export-trie payload overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: trie.offset,
            end: payload_end,
        });
    }
    for routines in &image.routines {
        let end = routines
            .source_offset
            .checked_add(routines.source_size)
            .ok_or_else(|| execution(path, "Mach-O routines range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: routines.source_offset,
            end,
        });
        for address in [routines.init_address, routines.term_address] {
            let Some(segment) = image.segments.iter().find(|segment| {
                address >= segment.vm_address && address - segment.vm_address < segment.file_size
            }) else {
                continue;
            };
            let file_offset = segment
                .file_offset
                .checked_add(address - segment.vm_address)
                .ok_or_else(|| execution(path, "Mach-O routine address overflowed.".into()))?;
            let address_end = file_offset
                .checked_add(1)
                .ok_or_else(|| execution(path, "Mach-O routine range overflowed.".into()))?;
            locations.push(Location::FileOffsetRange {
                start: file_offset,
                end: address_end,
            });
        }
    }
    for hints in &image.twolevel_hints {
        let end = hints
            .source_offset
            .checked_add(hints.source_size)
            .ok_or_else(|| execution(path, "Mach-O two-level-hints range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: hints.source_offset,
            end,
        });
        if !hints.valid || hints.count == 0 {
            continue;
        }
        let table_end = hints
            .offset
            .checked_add(hints.count.checked_mul(4).ok_or_else(|| {
                execution(path, "Mach-O two-level-hints table size overflowed.".into())
            })?)
            .ok_or_else(|| execution(path, "Mach-O two-level-hints table overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: hints.offset,
            end: table_end,
        });
        for entry in &hints.entries {
            let entry_end = entry
                .source_offset
                .checked_add(entry.source_size)
                .ok_or_else(|| execution(path, "Mach-O two-level-hint entry overflowed.".into()))?;
            if entry.valid {
                locations.push(Location::FileOffsetRange {
                    start: entry.source_offset,
                    end: entry_end,
                });
            }
        }
    }
    for prebound in &image.prebound_dylibs {
        let end = prebound
            .source_offset
            .checked_add(prebound.source_size)
            .ok_or_else(|| execution(path, "Mach-O prebound-dylib range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: prebound.source_offset,
            end,
        });
        if prebound.linked_modules_valid && prebound.linked_modules_count != 0 {
            let modules_end = prebound
                .linked_modules_offset
                .checked_add(prebound.linked_modules_count)
                .ok_or_else(|| {
                    execution(
                        path,
                        "Mach-O prebound linked-modules range overflowed.".into(),
                    )
                })?;
            locations.push(Location::FileOffsetRange {
                start: prebound.linked_modules_offset,
                end: modules_end,
            });
        }
    }
    if let Some(entrypoint) = image
        .entrypoint
        .as_ref()
        .filter(|entrypoint| entrypoint.valid)
    {
        let command_end = entrypoint
            .source_offset
            .checked_add(entrypoint.source_size)
            .ok_or_else(|| execution(path, "Mach-O entrypoint command range overflowed.".into()))?;
        if entrypoint.source_size != 0 {
            locations.push(Location::FileOffsetRange {
                start: entrypoint.source_offset,
                end: command_end,
            });
        }
        let end = entrypoint
            .file_offset
            .checked_add(1)
            .ok_or_else(|| execution(path, "Mach-O entrypoint range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: entrypoint.file_offset,
            end,
        });
    }

    add_function_start_locations(path, image, &mut locations)?;
    add_uuid_location(path, image, &mut locations)?;
    add_data_in_code_locations(path, image, &mut locations)?;
    add_rebase_locations(path, image, &mut locations)?;
    add_dyld_info_locations(path, image, &mut locations)?;
    add_code_signature_locations(path, image, &mut locations)?;
    add_encryption_locations(path, image, &mut locations)?;
    add_bind_locations(path, image, &mut locations)?;
    add_chained_import_locations(path, image, &mut locations)?;
    add_indirect_symbol_locations(path, image, &mut locations)?;
    add_note_locations(path, image, &mut locations)?;
    add_unix_thread_locations(path, image, &mut locations)?;
    add_fileset_entry_locations(path, image, &mut locations)?;
    add_build_metadata_locations(path, image, &mut locations)?;
    add_path_locations(path, image, &mut locations)?;
    for record in &image.subordinate_paths {
        let end = record
            .command_offset
            .checked_add(record.command_size)
            .ok_or_else(|| execution(path, "Mach-O subordinate path range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: record.command_offset,
            end,
        });
    }
    add_dylib_locations(path, image, &mut locations)?;
    add_export_locations(path, image, &mut locations)?;
    add_nlist_locations(path, image, &mut locations)?;
    if let Some(dysymtab) = &image.dysymtab {
        let end = dysymtab
            .source_offset
            .checked_add(dysymtab.source_size)
            .ok_or_else(|| execution(path, "Mach-O dysymtab range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: dysymtab.source_offset,
            end,
        });
        if dysymtab.indirect_source_size != 0 {
            let indirect_end = dysymtab
                .indirect_source_offset
                .checked_add(dysymtab.indirect_source_size)
                .ok_or_else(|| {
                    execution(
                        path,
                        "Mach-O indirect-symbol table range overflowed.".into(),
                    )
                })?;
            locations.push(Location::FileOffsetRange {
                start: dysymtab.indirect_source_offset,
                end: indirect_end,
            });
        }
        for table in &dysymtab.tables {
            if !table.valid || table.count == 0 {
                continue;
            }
            let table_end = table
                .source_offset
                .checked_add(table.source_size)
                .ok_or_else(|| execution(path, "Mach-O dysymtab table range overflowed.".into()))?;
            locations.push(Location::FileOffsetRange {
                start: table.source_offset,
                end: table_end,
            });
        }
    }
    if let Some(fixups) = &image.chained_fixups {
        if fixups.valid && fixups.data_size != 0 {
            let end = fixups
                .data_offset
                .checked_add(fixups.data_size)
                .ok_or_else(|| execution(path, "Mach-O chained-fixups range overflowed.".into()))?;
            locations.push(Location::FileOffsetRange {
                start: fixups.data_offset,
                end,
            });
        }
    }
    for options in &image.linker_options {
        if options.command_size == 0 {
            continue;
        }
        let end = options
            .command_offset
            .checked_add(options.command_size)
            .ok_or_else(|| execution(path, "Mach-O linker-option range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: options.command_offset,
            end,
        });
        for option in &options.option_records {
            if option.source_size == 0 {
                continue;
            }
            let option_end = option
                .source_offset
                .checked_add(option.source_size)
                .ok_or_else(|| {
                    execution(path, "Mach-O linker-option string range overflowed.".into())
                })?;
            locations.push(Location::FileOffsetRange {
                start: option.source_offset,
                end: option_end,
            });
        }
    }

    Ok(locations)
}

fn add_uuid_location(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    let Some(start) = image.uuid_source_offset else {
        return Ok(());
    };
    if image.uuid_source_size == 0 {
        return Ok(());
    }
    let end = start
        .checked_add(image.uuid_source_size)
        .ok_or_else(|| execution(path, "Mach-O UUID command range overflowed.".into()))?;
    locations.push(Location::FileOffsetRange { start, end });
    Ok(())
}

fn add_chained_import_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for import in &image.chained_imports {
        if import.source_size == 0 {
            continue;
        }
        let end = import
            .source_offset
            .checked_add(import.source_size)
            .ok_or_else(|| execution(path, "Mach-O chained-import range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: import.source_offset,
            end,
        });
    }
    Ok(())
}

fn add_data_in_code_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for table in &image.data_in_code_tables {
        let command_end = table
            .source_offset
            .checked_add(table.source_size)
            .ok_or_else(|| {
                execution(path, "Mach-O data-in-code command range overflowed.".into())
            })?;
        locations.push(Location::FileOffsetRange {
            start: table.source_offset,
            end: command_end,
        });
        if !table.valid || table.size == 0 {
            continue;
        }
        let table_end = table
            .offset
            .checked_add(table.size)
            .ok_or_else(|| execution(path, "Mach-O data-in-code table range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: table.offset,
            end: table_end,
        });
    }
    for record in &image.data_in_code {
        let source_end = record
            .source_offset
            .checked_add(record.source_size)
            .ok_or_else(|| {
                execution(path, "Mach-O data-in-code record range overflowed.".into())
            })?;
        locations.push(Location::FileOffsetRange {
            start: record.source_offset,
            end: source_end,
        });
        if !record.valid || record.length == 0 {
            continue;
        }
        let end = record
            .offset
            .checked_add(u64::from(record.length))
            .ok_or_else(|| execution(path, "Mach-O data-in-code range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: record.offset,
            end,
        });
    }
    Ok(())
}

fn add_code_signature_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for signature in &image.code_signatures {
        if !signature.valid || signature.size == 0 {
            continue;
        }
        let end = signature
            .offset
            .checked_add(signature.size)
            .ok_or_else(|| execution(path, "Mach-O code-signature range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: signature.offset,
            end,
        });
        if let (Some(offset), Some(size)) =
            (signature.entitlements_offset, signature.entitlements_size)
        {
            if size == 0 {
                continue;
            }
            let end = offset
                .checked_add(size)
                .ok_or_else(|| execution(path, "Mach-O entitlement range overflowed.".into()))?;
            locations.push(Location::FileOffsetRange { start: offset, end });
        }
    }
    for child in &image.code_signature_children {
        if !child.valid || child.size == 0 {
            continue;
        }
        let end = child.offset.checked_add(child.size).ok_or_else(|| {
            execution(path, "Mach-O code-signature child range overflowed.".into())
        })?;
        locations.push(Location::FileOffsetRange {
            start: child.offset,
            end,
        });
    }
    Ok(())
}

fn add_rebase_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for rebase in &image.rebases {
        if rebase.source_size != 0 {
            let source_end = rebase
                .source_offset
                .checked_add(rebase.source_size)
                .ok_or_else(|| execution(path, "Mach-O rebase stream range overflowed.".into()))?;
            locations.push(Location::FileOffsetRange {
                start: rebase.source_offset,
                end: source_end,
            });
        }
        if !rebase.valid {
            continue;
        }
        let Some(segment) = image.segments.get(usize::from(rebase.segment)) else {
            continue;
        };
        let file_offset = segment
            .file_offset
            .checked_add(rebase.offset)
            .ok_or_else(|| execution(path, "Mach-O rebase location overflowed.".into()))?;
        let end = file_offset
            .checked_add(1)
            .ok_or_else(|| execution(path, "Mach-O rebase range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: file_offset,
            end,
        });
    }
    Ok(())
}

fn add_bind_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for bind in &image.binds {
        if bind.source_size == 0 {
            continue;
        }
        let end = bind
            .source_offset
            .checked_add(bind.source_size)
            .ok_or_else(|| execution(path, "Mach-O bind stream range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: bind.source_offset,
            end,
        });
    }
    Ok(())
}

fn add_dyld_info_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for command in &image.dyld_info {
        let command_end = command
            .source_offset
            .checked_add(command.source_size)
            .ok_or_else(|| execution(path, "Mach-O dyld-info command range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: command.source_offset,
            end: command_end,
        });

        for stream in [
            command.rebase.as_ref(),
            command.bind.as_ref(),
            command.weak_bind.as_ref(),
            command.lazy_bind.as_ref(),
            command.exports.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if !stream.valid || stream.size == 0 {
                continue;
            }
            let stream_end = stream.offset.checked_add(stream.size).ok_or_else(|| {
                execution(path, "Mach-O dyld-info stream range overflowed.".into())
            })?;
            locations.push(Location::FileOffsetRange {
                start: stream.offset,
                end: stream_end,
            });
        }
    }
    Ok(())
}

fn add_encryption_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for encryption in &image.encryption_info {
        let command_end = encryption
            .source_offset
            .checked_add(encryption.source_size)
            .ok_or_else(|| execution(path, "Mach-O encryption command range overflowed.".into()))?;
        if encryption.source_size != 0 {
            locations.push(Location::FileOffsetRange {
                start: encryption.source_offset,
                end: command_end,
            });
        }

        if !encryption.valid || encryption.size == 0 {
            continue;
        }

        let end = encryption
            .offset
            .checked_add(encryption.size)
            .ok_or_else(|| execution(path, "Mach-O encrypted range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: encryption.offset,
            end,
        });
    }
    Ok(())
}

fn add_indirect_symbol_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for symbol in &image.indirect_symbols {
        let end = symbol
            .source_offset
            .checked_add(1)
            .ok_or_else(|| execution(path, "Mach-O indirect-symbol range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: symbol.source_offset,
            end,
        });
    }
    Ok(())
}

fn add_note_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for note in &image.notes {
        let source_end = note
            .source_offset
            .checked_add(note.source_size)
            .ok_or_else(|| execution(path, "Mach-O note command range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: note.source_offset,
            end: source_end,
        });

        if !note.valid || note.size == 0 {
            continue;
        }
        let payload_end = note
            .offset
            .checked_add(note.size)
            .ok_or_else(|| execution(path, "Mach-O note range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: note.offset,
            end: payload_end,
        });
    }
    Ok(())
}

fn add_unix_thread_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for thread in &image.unix_threads {
        let Some(pc) = thread.pc else {
            continue;
        };
        let Some(segment) = image.segments.iter().find(|segment| {
            pc >= segment.vm_address && pc - segment.vm_address < segment.file_size
        }) else {
            continue;
        };
        let file_offset = segment
            .file_offset
            .checked_add(pc - segment.vm_address)
            .ok_or_else(|| execution(path, "Mach-O thread PC location overflowed.".into()))?;
        let end = file_offset
            .checked_add(1)
            .ok_or_else(|| execution(path, "Mach-O thread PC range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: file_offset,
            end,
        });
    }
    Ok(())
}

fn add_fileset_entry_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for entry in &image.fileset_entries {
        let source_end = entry
            .source_offset
            .checked_add(entry.source_size)
            .ok_or_else(|| execution(path, "Mach-O fileset command range overflowed.".into()))?;
        if entry.source_size != 0 {
            locations.push(Location::FileOffsetRange {
                start: entry.source_offset,
                end: source_end,
            });
        }
        if let Some(start) = entry.entry_id_source_offset {
            let end = start
                .checked_add(entry.entry_id_source_size)
                .ok_or_else(|| execution(path, "Mach-O fileset ID range overflowed.".into()))?;
            if entry.entry_id_source_size != 0 {
                locations.push(Location::FileOffsetRange { start, end });
            }
        }
        if !entry.valid {
            continue;
        }
        let file_offset = entry
            .file_offset
            .ok_or_else(|| execution(path, "Mach-O fileset entry has no file offset.".into()))?;
        let end = file_offset
            .checked_add(1)
            .ok_or_else(|| execution(path, "Mach-O fileset entry range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: file_offset,
            end,
        });
    }
    Ok(())
}

fn add_build_metadata_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for metadata in &image.build_metadata {
        let end = metadata
            .source_offset
            .checked_add(metadata.source_size)
            .ok_or_else(|| execution(path, "Mach-O build metadata range overflowed.".into()))?;
        if metadata.source_size != 0 {
            locations.push(Location::FileOffsetRange {
                start: metadata.source_offset,
                end,
            });
        }
    }
    for tool in &image.build_tools {
        let end = tool
            .source_offset
            .checked_add(tool.source_size)
            .ok_or_else(|| execution(path, "Mach-O build tool range overflowed.".into()))?;
        if tool.source_size != 0 {
            locations.push(Location::FileOffsetRange {
                start: tool.source_offset,
                end,
            });
        }
    }
    Ok(())
}

fn add_path_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for record in image
        .rpath_records
        .iter()
        .chain(image.dyld_environment.iter())
        .chain(image.dylinkers.iter())
    {
        if record.command_size == 0 {
            continue;
        }
        let end = record
            .command_offset
            .checked_add(record.command_size)
            .ok_or_else(|| execution(path, "Mach-O path command range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: record.command_offset,
            end,
        });
        if let Some(string_start) = record.string_source_offset {
            let string_end = string_start
                .checked_add(record.string_source_size)
                .ok_or_else(|| execution(path, "Mach-O path string range overflowed.".into()))?;
            if record.string_source_size != 0 {
                locations.push(Location::FileOffsetRange {
                    start: string_start,
                    end: string_end,
                });
            }
        }
    }
    Ok(())
}

fn add_dylib_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for dylib in &image.dylibs {
        if dylib.command_size == 0 {
            continue;
        }
        let end = dylib
            .command_offset
            .checked_add(dylib.command_size)
            .ok_or_else(|| execution(path, "Mach-O dylib command range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: dylib.command_offset,
            end,
        });
        if let Some(start) = dylib.name_source_offset {
            let name_end = start
                .checked_add(dylib.name_source_size)
                .ok_or_else(|| execution(path, "Mach-O dylib name range overflowed.".into()))?;
            if dylib.name_source_size != 0 {
                locations.push(Location::FileOffsetRange {
                    start,
                    end: name_end,
                });
            }
        }
    }
    Ok(())
}

fn add_export_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for export in &image.export_records {
        if !export.valid {
            continue;
        }
        let end = export
            .terminal_offset
            .checked_add(1)
            .ok_or_else(|| execution(path, "Mach-O export terminal range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: export.terminal_offset,
            end,
        });
    }
    Ok(())
}

fn add_nlist_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for symbol in &image.nlist_symbols {
        let end = symbol
            .source_offset
            .checked_add(1)
            .ok_or_else(|| execution(path, "Mach-O nlist source range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: symbol.source_offset,
            end,
        });
    }
    Ok(())
}

fn add_function_start_locations(
    path: &str,
    image: &macho::Image,
    locations: &mut Vec<Location>,
) -> Result<(), Failure> {
    for table in &image.function_starts_tables {
        let command_end = table
            .source_offset
            .checked_add(table.source_size)
            .ok_or_else(|| {
                execution(
                    path,
                    "Mach-O function-starts command range overflowed.".into(),
                )
            })?;
        locations.push(Location::FileOffsetRange {
            start: table.source_offset,
            end: command_end,
        });
        if !table.valid || table.size == 0 {
            continue;
        }
        let table_end = table.offset.checked_add(table.size).ok_or_else(|| {
            execution(
                path,
                "Mach-O function-starts table range overflowed.".into(),
            )
        })?;
        locations.push(Location::FileOffsetRange {
            start: table.offset,
            end: table_end,
        });
    }
    for record in &image.function_start_records {
        let source_end = record
            .source_offset
            .checked_add(record.source_size)
            .ok_or_else(|| {
                execution(
                    path,
                    "Mach-O function-start source range overflowed.".into(),
                )
            })?;
        locations.push(Location::FileOffsetRange {
            start: record.source_offset,
            end: source_end,
        });
        if !record.valid {
            continue;
        }
        let address = record.address;
        let Some(segment) = image.segments.iter().find(|segment| {
            segment.initial_permissions.execute
                && address >= segment.vm_address
                && address - segment.vm_address < segment.file_size
        }) else {
            continue;
        };
        let file_delta = address - segment.vm_address;
        let file_offset = segment
            .file_offset
            .checked_add(file_delta)
            .ok_or_else(|| execution(path, "Mach-O function-start location overflowed.".into()))?;
        let end = file_offset
            .checked_add(1)
            .ok_or_else(|| execution(path, "Mach-O function-start range overflowed.".into()))?;
        locations.push(Location::FileOffsetRange {
            start: file_offset,
            end,
        });
    }
    Ok(())
}

fn admit_report_length(path: &str, report: &Report) -> Result<(), Failure> {
    match json_output::admitted_length(report, MAX_OUTPUT_BYTES) {
        Ok(_) => Ok(()),
        Err(json_output::Error::Limit { maximum }) => resource(path, maximum),
        Err(json_output::Error::Encoding(error)) => Err(execution(path, error.to_string())),
    }
}

fn resource(path: &str, maximum: usize) -> Result<(), Failure> {
    let mut fields = BTreeMap::from([
        ("operation", Detail::Text(OPERATION.into())),
        ("resource", Detail::Text("transport".into())),
        (
            "reason",
            Detail::Text(format!(
                "Complete Mach-O metadata for {path} exceeds the inline output budget."
            )),
        ),
    ]);
    fields.insert(
        "reported_limits",
        Detail::Fields(BTreeMap::from([(
            "maximum_output_bytes",
            Detail::Count(maximum as u64),
        )])),
    );
    Err(Failure::new(
        "resource_constraint",
        "resource_constraint",
        "Complete Mach-O metadata exceeds the inline output budget.".into(),
        false,
        "Use a smaller artifact or export complete retained Evidence.".into(),
        fields,
    ))
}

fn execution(path: &str, reason: String) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        "Analysis could not complete.".into(),
        false,
        "Review the reported diagnostics and retry with a supported Mach-O image.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("provider_id", Detail::Text(PROVIDER.id.into())),
            (
                "diagnostics",
                Detail::Fields(BTreeMap::from([
                    ("path", Detail::Text(path.into())),
                    ("reason", Detail::Text(reason)),
                ])),
            ),
        ]),
    )
}
