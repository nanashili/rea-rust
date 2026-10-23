use rea_rust_analysis::macho;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32be(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn lists_thin_architecture_slice_metadata() {
    let mut bytes = vec![0u8; 32];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 8, 2);

    let slices = macho::architectures(&bytes).expect("thin architecture is listed");
    assert_eq!(slices.len(), 1);
    assert_eq!(slices[0].name, "arm64");
    assert_eq!(slices[0].cpu_subtype_name, "ARM64E");
    assert_eq!(slices[0].file_offset, 0);
    assert_eq!(slices[0].size, 32);
    assert!(slices[0].valid);
}

#[test]
fn conflicting_uuid_commands_remain_unknown() {
    let header = 32;
    let command = 24;
    let mut bytes = vec![0u8; header + command * 2];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, (command * 2) as u32);

    for (index, value) in [0x11u8, 0x22u8].into_iter().enumerate() {
        let offset = header + index * command;
        put32(&mut bytes, offset, 0x1b);
        put32(&mut bytes, offset + 4, command as u32);
        bytes[offset + 8..offset + 24].fill(value);
    }

    let image = macho::read(&bytes).expect("conflicting UUID commands remain readable");
    assert!(image.uuid.is_none());
    assert!(image.uuid_raw.is_none());
    assert!(image.uuid_source_offset.is_none());
    assert!(
        image
            .uuid_issues
            .iter()
            .any(|issue| issue.contains("Conflicting LC_UUID"))
    );
}

#[test]
fn lists_bounded_universal_architecture_slices() {
    let mut bytes = vec![0u8; 0x300];
    put32be(&mut bytes, 0, 0xcafebabe);
    put32be(&mut bytes, 4, 2);

    put32be(&mut bytes, 8, 0x01000007);
    put32be(&mut bytes, 12, 3);
    put32be(&mut bytes, 16, 0x100);
    put32be(&mut bytes, 20, 0x80);
    put32be(&mut bytes, 24, 2);

    put32be(&mut bytes, 28, 0x0100000c);
    put32be(&mut bytes, 32, 2);
    put32be(&mut bytes, 36, 0x180);
    put32be(&mut bytes, 40, 0x80);
    put32be(&mut bytes, 44, 3);

    let slices = macho::architectures(&bytes).expect("universal slices are listed");
    assert_eq!(slices.len(), 2);
    assert_eq!(slices[0].cpu_name, "x86_64");
    assert_eq!(slices[0].cpu_subtype_name, "X86_64_ALL");
    assert_eq!(slices[0].file_offset, 0x100);
    assert_eq!(slices[0].alignment, Some(2));
    assert!(slices[0].valid);
    assert_eq!(slices[1].cpu_name, "arm64");
    assert_eq!(slices[1].file_offset, 0x180);
    assert!(slices[1].valid);
}

#[test]
fn rejects_truncated_universal_architecture_table() {
    let mut bytes = vec![0u8; 12];
    put32be(&mut bytes, 0, 0xcafebabe);
    put32be(&mut bytes, 4, 1);

    let error = macho::architectures(&bytes).expect_err("truncated table must fail");
    assert!(
        error
            .to_string()
            .contains("architecture table is truncated")
    );
}

#[test]
fn rejects_four_byte_aligned_command_in_a_64_bit_image() {
    let header = 32;
    let command = 12;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x7000_0000);
    put32(&mut bytes, header + 4, command as u32);

    let error = macho::read(&bytes).expect_err("64-bit command alignment is required");
    assert!(error.to_string().contains("Invalid Mach-O load command"));
}

#[test]
fn accepts_four_byte_aligned_command_in_a_32_bit_image() {
    let header = 28;
    let command = 12;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedface);
    put32(&mut bytes, 4, 7);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x7000_0000);
    put32(&mut bytes, header + 4, command as u32);

    let image = macho::read(&bytes).expect("32-bit commands use four-byte alignment");
    assert_eq!(image.load_commands.len(), 1);
    assert_eq!(image.load_commands[0].source_size, command as u64);
}

#[test]
fn reads_load_commands_without_running_apple_tools() {
    let header = 32;
    let segment = 72;
    let main = 24;
    let dylib = 32;
    let symtab = 24;
    let command_bytes = segment + main + dylib + symtab;
    let symbol_offset = header + command_bytes;
    let string_offset = symbol_offset + 16 * 2;
    let mut bytes = vec![0u8; string_offset + 32];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 8, 2);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 4);
    put32(&mut bytes, 20, command_bytes as u32);
    put32(&mut bytes, 24, 0x200000);

    let segment_at = header;
    put32(&mut bytes, segment_at, 0x19);
    put32(&mut bytes, segment_at + 4, segment as u32);
    bytes[segment_at + 8..segment_at + 14].copy_from_slice(b"__TEXT");
    put64(&mut bytes, segment_at + 24, 0x100000000);
    put64(&mut bytes, segment_at + 32, 0x1000);
    put64(&mut bytes, segment_at + 40, 0);
    put64(&mut bytes, segment_at + 48, 0x1000);
    put32(&mut bytes, segment_at + 56, 5);
    put32(&mut bytes, segment_at + 60, 5);

    let main_at = segment_at + segment;
    put32(&mut bytes, main_at, 0x80000028);
    put32(&mut bytes, main_at + 4, main as u32);
    put64(&mut bytes, main_at + 8, 0x400);

    let dylib_at = main_at + main;
    put32(&mut bytes, dylib_at, 0xc);
    put32(&mut bytes, dylib_at + 4, dylib as u32);
    put32(&mut bytes, dylib_at + 8, 24);
    bytes[dylib_at + 24..dylib_at + 32].copy_from_slice(b"libX.dyl");

    let symtab_at = dylib_at + dylib;
    put32(&mut bytes, symtab_at, 0x2);
    put32(&mut bytes, symtab_at + 4, symtab as u32);
    put32(&mut bytes, symtab_at + 8, symbol_offset as u32);
    put32(&mut bytes, symtab_at + 12, 2);
    put32(&mut bytes, symtab_at + 16, string_offset as u32);
    put32(&mut bytes, symtab_at + 20, 19);
    put32(&mut bytes, symbol_offset, 1);
    bytes[symbol_offset + 4] = 0x0f;
    put64(&mut bytes, symbol_offset + 8, 0x1000);
    put32(&mut bytes, symbol_offset + 16, 11);
    bytes[symbol_offset + 20] = 0x01;
    put64(&mut bytes, symbol_offset + 24, 0);
    bytes[string_offset..string_offset + 19].copy_from_slice(b"\0_exported\0_import\0");

    let image = macho::read(&bytes).expect("valid thin Mach-O");
    assert_eq!(image.word_size, 64);
    assert_eq!(image.cpu, 0x0100000c);
    assert_eq!(image.cpu_name, "arm64");
    assert_eq!(image.cpu_subtype_name, "ARM64E");
    assert_eq!(image.cpu_subtype, 2);
    assert_eq!(image.file_type_name, "MH_EXECUTE");
    assert_eq!(image.flag_names, ["MH_PIE"]);
    assert_eq!(image.load_commands.len(), 4);
    assert_eq!(image.load_commands[0].index, 0);
    assert_eq!(image.load_commands[0].command, 0x19);
    assert_eq!(image.load_commands[0].kind, "LC_SEGMENT_64");
    assert_eq!(image.load_commands[0].source_offset, header as u64);
    assert_eq!(image.load_commands[0].source_size, segment as u64);
    assert!(image.load_commands[0].valid);
    assert_eq!(
        image.entrypoint.as_ref().map(|entry| entry.file_offset),
        Some(0x400)
    );
    assert_eq!(image.dependencies[0].path, "libX.dyl");
    assert_eq!(image.dependencies[0].name_offset, Some(24));
    assert_eq!(image.dependencies[0].source_offset, dylib_at as u64);
    assert_eq!(image.dependencies[0].source_size, dylib as u64);
    assert_eq!(
        image.dependencies[0].current_version.as_deref(),
        Some("0.0.0")
    );
    assert_eq!(
        image.dependencies[0].compatibility_version.as_deref(),
        Some("0.0.0")
    );
    assert_eq!(image.segments[0].name, "__TEXT");
    assert!(image.segments[0].maximum_permissions.read);
    assert!(!image.segments[0].maximum_permissions.write);
    assert!(image.segments[0].maximum_permissions.execute);
    assert_eq!(image.segments[0].maximum_permissions.raw, "0x5");
    assert_eq!(image.exports[0].name, "_exported");
    assert_eq!(image.imports[0].name, "_import");
    assert_eq!(image.nlist_symbols.len(), 2);
    assert_eq!(image.nlist_symbols[0].n_type, 0x0f);
    assert_eq!(image.nlist_symbols[0].n_sect, 0);
    assert_eq!(image.nlist_symbols[0].n_desc, 0);
    assert_eq!(image.nlist_symbols[0].n_value, 0x1000);
    assert_eq!(image.nlist_symbols[0].classification, Some("section"));
    assert!(image.nlist_symbols[0].valid);
}

#[test]
fn preserves_section_alignment_exponent_and_layout() {
    let header = 32;
    let segment = 72;
    let section = 80;
    let command = segment + section;
    let mut bytes = vec![0u8; header + command + 0x1000];

    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);

    let segment_at = header;
    put32(&mut bytes, segment_at, 0x19);
    put32(&mut bytes, segment_at + 4, command as u32);
    bytes[segment_at + 8..segment_at + 14].copy_from_slice(b"__TEXT");
    put64(&mut bytes, segment_at + 24, 0x100000000);
    put64(&mut bytes, segment_at + 32, 0x1000);
    put64(&mut bytes, segment_at + 40, 0);
    put64(&mut bytes, segment_at + 48, 0x1000);
    put32(&mut bytes, segment_at + 56, 5);
    put32(&mut bytes, segment_at + 60, 5);
    put32(&mut bytes, segment_at + 64, 1);

    let section_at = segment_at + segment;
    bytes[section_at..section_at + 6].copy_from_slice(b"__text");
    bytes[section_at + 16..section_at + 22].copy_from_slice(b"__TEXT");
    put64(&mut bytes, section_at + 32, 0x100000000);
    put64(&mut bytes, section_at + 40, 0x1000);
    put32(&mut bytes, section_at + 48, 0);
    put32(&mut bytes, section_at + 52, 4);
    put32(&mut bytes, section_at + 64, 0x80000000);

    let image = macho::read(&bytes).expect("valid section metadata");
    assert_eq!(image.sections.len(), 1);
    assert_eq!(image.sections[0].name, "__text");
    assert_eq!(image.sections[0].segment, "__TEXT");
    assert_eq!(image.sections[0].name_bytes, b"__text");
    assert!(image.sections[0].name_utf8_valid);
    assert!(image.sections[0].segment_utf8_valid);
    assert_eq!(image.sections[0].alignment, 4);
    assert_eq!(image.sections[0].alignment_bytes, Some(16));
    assert_eq!(image.sections[0].flags, 0x80000000);
    assert_eq!(
        image.sections[0].flag_names,
        ["S_REGULAR", "S_ATTR_LIVE_SUPPORT"]
    );
}

#[test]
fn retains_invalid_segment_and_section_name_bytes() {
    let header = 32;
    let segment = 72;
    let section = 80;
    let command = segment + section;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x19);
    put32(&mut bytes, header + 4, command as u32);
    bytes[header + 8..header + 10].copy_from_slice(&[0xff, 0]);
    put64(&mut bytes, header + 24, 0x1000);
    put64(&mut bytes, header + 32, 0x1000);
    put64(&mut bytes, header + 40, 0);
    let file_size = bytes.len() as u64;
    put64(&mut bytes, header + 48, file_size);
    put32(&mut bytes, header + 56, 5);
    put32(&mut bytes, header + 60, 5);
    put32(&mut bytes, header + 64, 1);
    let section_at = header + segment;
    bytes[section_at..section_at + 2].copy_from_slice(&[0xfe, 0]);
    bytes[section_at + 16..section_at + 18].copy_from_slice(&[0xff, 0]);

    let image = macho::read(&bytes).expect("invalid fixed names remain observable");
    let segment = &image.segments[0];
    assert!(!segment.name_utf8_valid);
    assert_eq!(segment.name_bytes, vec![0xff]);
    let section = &image.sections[0];
    assert!(!section.name_utf8_valid);
    assert_eq!(section.name_bytes, vec![0xfe]);
    assert!(!section.segment_utf8_valid);
    assert_eq!(section.segment_bytes, vec![0xff]);
}

#[test]
fn preserves_uuid_bytes_and_command_provenance() {
    let header = 32;
    let command = 24;
    let mut bytes = vec![0u8; header + command];
    let uuid = [
        0x00, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, 0xdd, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xee,
        0xff,
    ];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x1b);
    put32(&mut bytes, header + 4, command as u32);
    bytes[header + 8..header + 24].copy_from_slice(&uuid);

    let image = macho::read(&bytes).expect("UUID command is decoded");
    assert_eq!(
        image.uuid.as_deref(),
        Some("00112233-aabb-ccdd-4455-66778899eeff")
    );
    assert_eq!(image.uuid_raw.as_deref(), Some(uuid.as_slice()));
    assert_eq!(image.uuid_source_offset, Some(header as u64));
    assert_eq!(image.uuid_source_size, command as u64);
}

#[test]
fn decodes_lazy_load_dylib_as_a_dependency_kind() {
    let header = 32;
    let command = 40;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x20);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 24);
    bytes[header + 24..header + 24 + 11].copy_from_slice(b"libLazy.dyl");

    let image = macho::read(&bytes).expect("valid lazy dylib command");
    assert_eq!(image.dylibs[0].kind, "lazy");
    assert_eq!(image.dependencies[0].kind, "lazy");
    assert_eq!(image.dependencies[0].path, "libLazy.dyl");
    assert_eq!(image.load_commands[0].kind, "LC_LAZY_LOAD_DYLIB");
}

#[test]
fn decodes_id_dylib_as_an_identity_record() {
    let header = 32;
    let command = 40;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 6);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0xd);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 24);
    bytes[header + 24..header + 24 + 11].copy_from_slice(b"libSelf.dyl");

    let image = macho::read(&bytes).expect("valid identity dylib command");
    assert_eq!(image.dylibs[0].kind, "id");
    assert_eq!(image.dependencies[0].kind, "id");
    assert_eq!(image.load_commands[0].kind, "LC_ID_DYLIB");
}

#[test]
fn decodes_source_version_command_with_raw_value() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x2a);
    put32(&mut bytes, header + 4, command as u32);
    put64(&mut bytes, header + 8, 0x0001_0002_0003_0004);

    let image = macho::read(&bytes).expect("valid source-version command");
    assert_eq!(image.source_versions[0].raw, 0x0001_0002_0003_0004);
    assert_eq!(image.source_versions[0].version, "256.8.0.192.4");
    assert_eq!(image.source_versions[0].source_offset, header as u64);
    assert_eq!(image.load_commands[0].kind, "LC_SOURCE_VERSION");
}

#[test]
fn decodes_linker_optimization_hints_range() {
    let header = 32;
    let command = 16;
    let data_offset = (header + command) as u32;
    let mut bytes = vec![0u8; header + command + 4];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x2e);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, data_offset);
    put32(&mut bytes, header + 12, 4);

    let image = macho::read(&bytes).expect("valid optimization-hints command");
    assert_eq!(
        image.linker_optimization_hints[0].offset,
        data_offset as u64
    );
    assert_eq!(image.linker_optimization_hints[0].size, 4);
    assert!(image.linker_optimization_hints[0].valid);
    assert_eq!(image.load_commands[0].kind, "LC_LINKER_OPTIMIZATION_HINTS");
}

#[test]
fn retains_out_of_file_linker_optimization_hints() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x2e);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 0x1000);
    put32(&mut bytes, header + 12, 4);

    let image = macho::read(&bytes).expect("invalid optimization hints remain observable");
    assert!(!image.linker_optimization_hints[0].valid);
}

#[test]
fn decodes_dyld_exports_trie_range() {
    let header = 32;
    let command = 16;
    let data_offset = (header + command) as u32;
    let mut bytes = vec![0u8; header + command + 4];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x8000_0033);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, data_offset);
    put32(&mut bytes, header + 12, 4);

    let image = macho::read(&bytes).expect("valid export trie command");
    assert_eq!(image.dyld_exports_tries[0].offset, data_offset as u64);
    assert!(image.dyld_exports_tries[0].valid);
    assert_eq!(image.load_commands[0].kind, "LC_DYLD_EXPORTS_TRIE");
}

#[test]
fn decodes_sub_library_path_record() {
    let header = 32;
    let command = 32;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x15);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 24);
    bytes[header + 24..header + 24 + 8].copy_from_slice(b"sub.dyl\0");

    let image = macho::read(&bytes).expect("valid sub-library command");
    assert_eq!(image.subordinate_paths[0].value.as_deref(), Some("sub.dyl"));
    assert_eq!(image.load_commands[0].kind, "LC_SUB_LIBRARY");
}

#[test]
fn decodes_32_bit_routines_command() {
    let header = 28;
    let command = 40;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedface);
    put32(&mut bytes, 4, 12);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x11);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 0x1000);
    put32(&mut bytes, header + 12, 0x2000);

    let image = macho::read(&bytes).expect("valid routines command");
    assert_eq!(image.routines[0].init_address, 0x1000);
    assert_eq!(image.routines[0].term_address, 0x2000);
    assert_eq!(image.load_commands[0].kind, "LC_ROUTINES");
}

#[test]
fn decodes_twolevel_hints_range_and_count() {
    let header = 32;
    let command = 16;
    let data_offset = (header + command) as u32;
    let mut bytes = vec![0u8; header + command + 8];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x16);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, data_offset);
    put32(&mut bytes, header + 12, 2);

    let image = macho::read(&bytes).expect("valid two-level hints command");
    assert_eq!(image.twolevel_hints[0].offset, data_offset as u64);
    assert_eq!(image.twolevel_hints[0].count, 2);
    assert!(image.twolevel_hints[0].valid);
    assert_eq!(image.twolevel_hints[0].entries.len(), 2);
    assert_eq!(image.twolevel_hints[0].entries[0].isub_image, 0);
    assert_eq!(image.twolevel_hints[0].entries[0].itoc, 0);
    assert_eq!(image.load_commands[0].kind, "LC_TWOLEVEL_HINTS");
}

#[test]
fn retains_malformed_twolevel_hints_table() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x16);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 0x1000);
    put32(&mut bytes, header + 12, 1);

    let image = macho::read(&bytes).expect("malformed hints table remains observable");
    assert!(!image.twolevel_hints[0].valid);
    assert!(image.twolevel_hints[0].entries.is_empty());
    assert!(
        image
            .twolevel_hint_issues
            .iter()
            .any(|issue| issue.contains("malformed"))
    );
}

#[test]
fn decodes_tvos_minimum_version_command() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x2f);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, (17 << 16) | (1 << 8));
    put32(&mut bytes, header + 12, 0x0011_0000);

    let image = macho::read(&bytes).expect("valid tvOS minimum version command");
    assert_eq!(image.build_metadata[0].command_kind, "LC_VERSION_MIN_TVOS");
    assert_eq!(image.build_metadata[0].min_os, Some("17.1.0".into()));
    assert_eq!(image.load_commands[0].kind, "LC_VERSION_MIN_TVOS");
}

#[test]
fn decodes_segment_split_info_range() {
    let header = 32;
    let command = 16;
    let data_offset = header + command;
    let mut bytes = vec![0u8; data_offset + 4];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x1e);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, data_offset as u32);
    put32(&mut bytes, header + 12, 4);

    let image = macho::read(&bytes).expect("valid segment-split-info command");
    let split_info = &image.segment_split_infos[0];
    assert_eq!(split_info.offset, data_offset as u64);
    assert_eq!(split_info.size, 4);
    assert!(split_info.valid);
}

#[test]
fn retains_out_of_file_segment_split_info_range() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x1e);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 0x1000);
    put32(&mut bytes, header + 12, 8);

    let image = macho::read(&bytes).expect("invalid segment-split range remains observable");
    assert!(!image.segment_split_infos[0].valid);
}

#[test]
fn decodes_prebound_dylib_name_and_module_table() {
    let header = 32;
    let command = 32;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x10);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 20);
    put32(&mut bytes, header + 12, 0);
    put32(&mut bytes, header + 16, (header + command) as u32);
    bytes[header + 20..header + 22].copy_from_slice(b"x\0");

    let image = macho::read(&bytes).expect("valid prebound dylib command");
    assert_eq!(image.prebound_dylibs[0].name.as_deref(), Some("x"));
    assert_eq!(image.prebound_dylibs[0].linked_modules_count, 0);
    assert!(image.prebound_dylibs[0].linked_modules_valid);
    assert!(image.prebound_dylibs[0].valid);
    assert_eq!(image.load_commands[0].kind, "LC_PREBOUND_DYLIB");
}

#[test]
fn retains_out_of_file_prebound_module_table() {
    let header = 32;
    let command = 32;
    let mut bytes = vec![0u8; header + command + 2];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x10);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 20);
    put32(&mut bytes, header + 12, 8);
    put32(&mut bytes, header + 16, 0x1000);
    bytes[header + 20..header + 22].copy_from_slice(b"x\0");

    let image = macho::read(&bytes).expect("invalid prebound module range remains observable");
    assert!(!image.prebound_dylibs[0].linked_modules_valid);
    assert!(!image.prebound_dylibs[0].valid);
}

#[test]
fn rejects_universal_images_without_selection() {
    let mut bytes = vec![0u8; 8];
    bytes[..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
    assert!(matches!(
        macho::read(&bytes),
        Err(macho::Error::Unsupported(_))
    ));
}

#[test]
fn decodes_export_trie_names_and_addresses() {
    let header = 32;
    let command = 48;
    let trie_offset = header + command;
    let trie = [0, 1, b'_', b'f', b'o', b'o', 0, 8, 2, 2, 0x10, 0];
    let bind = [0x70, 0, 0x40, b'_', b'i', b'm', b'p', 0, 0x90, 0];
    let bind_offset = trie_offset + trie.len();
    let mut bytes = vec![0u8; bind_offset + bind.len()];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x22);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 40, trie_offset as u32);
    put32(&mut bytes, header + 44, trie.len() as u32);
    put32(&mut bytes, header + 16, bind_offset as u32);
    put32(&mut bytes, header + 20, bind.len() as u32);
    bytes[trie_offset..bind_offset].copy_from_slice(&trie);
    bytes[bind_offset..].copy_from_slice(&bind);

    let image = macho::read(&bytes).expect("valid export trie");
    assert_eq!(image.dyld_info.len(), 1);
    assert_eq!(
        image.dyld_info[0].bind.as_ref().map(|range| range.offset),
        Some(bind_offset as u64)
    );
    assert!(
        image.dyld_info[0]
            .bind
            .as_ref()
            .is_some_and(|range| range.valid)
    );
    assert_eq!(
        image.dyld_info[0]
            .exports
            .as_ref()
            .map(|range| range.offset),
        Some(trie_offset as u64)
    );
    assert_eq!(image.exports.len(), 1);
    assert_eq!(image.exports[0].name, "_foo");
    assert_eq!(image.exports[0].address, 0x10);
    assert_eq!(image.export_records[0].flags, 2);
    assert!(image.export_records[0].flag_names.is_empty());
    assert_eq!(image.export_records[0].kind, "absolute");
    assert_eq!(
        image.export_records[0].source_offset,
        trie_offset as u64 + 9
    );
    assert_eq!(image.export_records[0].source_size, 2);
    assert!(image.export_records[0].valid);
    assert_eq!(image.binds[0].symbol, "_imp");
    assert_eq!(image.binds[0].segment, 0);
    assert_eq!(image.binds[0].source_offset, bind_offset as u64);
    assert_eq!(image.binds[0].source_size, bind.len() as u64);
}

#[test]
fn decodes_standalone_exports_trie_command() {
    let header = 32;
    let command = 16;
    let trie_offset = header + command;
    let trie = [0, 1, b'_', b'e', b'x', 0, 7, 2, 2, 0x20, 0];
    let mut bytes = vec![0u8; trie_offset + trie.len()];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x8000_0033);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, trie_offset as u32);
    put32(&mut bytes, header + 12, trie.len() as u32);
    bytes[trie_offset..].copy_from_slice(&trie);

    let image = macho::read(&bytes).expect("standalone exports trie is decoded");
    assert_eq!(image.dyld_exports_tries.len(), 1);
    assert!(image.dyld_exports_tries[0].valid);
    assert_eq!(image.exports.len(), 1);
    assert_eq!(image.exports[0].name, "_ex");
    assert_eq!(image.exports[0].address, 0x20);
}

#[test]
fn retains_out_of_file_standalone_exports_trie() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x8000_0033);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 0x1000);
    put32(&mut bytes, header + 12, 4);

    assert!(matches!(
        macho::read(&bytes),
        Err(macho::Error::Malformed(
            "Mach-O export trie is truncated or exceeds the limit"
        ))
    ));
}

#[test]
fn retains_unknown_dyld_bind_opcode_issue() {
    let header = 32;
    let command = 48;
    let stream_offset = header + command;
    let mut bytes = vec![0u8; stream_offset + 1];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x22);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 16, stream_offset as u32);
    put32(&mut bytes, header + 20, 1);
    bytes[stream_offset] = 0xe0;

    let image = macho::read(&bytes).expect("unknown bind opcode remains recoverable");
    assert!(
        image
            .bind_issues
            .iter()
            .any(|issue| issue.contains("Unknown Mach-O bind opcode"))
    );
}

#[test]
fn records_out_of_file_dyld_stream_range_without_reading_it() {
    let header = 32;
    let command = 48;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x22);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 16, 0xffff);
    put32(&mut bytes, header + 20, 4);

    let image = macho::read(&bytes).expect("out-of-file dyld range remains observable");
    let bind = image.dyld_info[0]
        .bind
        .as_ref()
        .expect("bind range is retained");
    assert_eq!(bind.offset, 0xffff);
    assert!(!bind.valid);
    assert!(
        image
            .bind_issues
            .iter()
            .any(|issue| issue.contains("truncated"))
    );
}

#[test]
fn decodes_chained_fixup_import_table() {
    let header = 32;
    let command = 16;
    let data = header + command;
    let imports = data + 28;
    let symbols = imports + 4;
    let name = b"_chain\0";
    let mut bytes = vec![0u8; symbols + name.len()];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x80000034);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, data as u32);
    put32(&mut bytes, header + 12, (28 + 4 + name.len()) as u32);
    put32(&mut bytes, data + 0, 0);
    put32(&mut bytes, data + 8, 28);
    put32(&mut bytes, data + 12, 32);
    put32(&mut bytes, data + 16, 1);
    put32(&mut bytes, data + 20, 1);
    put32(&mut bytes, data + 24, 0);
    put32(&mut bytes, imports, 1);
    bytes[symbols..].copy_from_slice(name);

    let image = macho::read(&bytes).expect("valid chained imports");
    assert_eq!(image.chained_imports.len(), 1);
    assert_eq!(image.chained_imports[0].symbol, "_chain");
    assert_eq!(image.chained_imports[0].ordinal, 1);
    assert_eq!(image.chained_imports[0].source_offset, imports as u64);
    assert_eq!(image.chained_imports[0].source_size, 4);
    let fixups = image.chained_fixups.as_ref().expect("fixup metadata");
    assert_eq!(fixups.data_offset, data as u64);
    assert_eq!(fixups.data_size, (28 + 4 + name.len()) as u64);
    assert_eq!(fixups.version, Some(0));
    assert_eq!(fixups.imports_count, Some(1));
    assert_eq!(fixups.imports_format, Some(1));
    assert!(fixups.valid);
}

#[test]
fn rejects_unsupported_chained_import_format() {
    let mut bytes = vec![0u8; 32 + 16 + 40];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, 16);
    put32(&mut bytes, 32, 0x80000034);
    put32(&mut bytes, 36, 16);
    put32(&mut bytes, 40, 48);
    put32(&mut bytes, 44, 40);
    put32(&mut bytes, 48 + 16, 1);
    put32(&mut bytes, 48 + 20, 99);
    assert!(matches!(
        macho::read(&bytes),
        Err(macho::Error::Unsupported(_))
    ));
}

#[test]
fn decodes_function_starts_as_image_relative_addresses() {
    let header = 32;
    let segment = 72;
    let function_starts = 16;
    let data_offset = header + segment + function_starts;
    let mut bytes = vec![0u8; data_offset + 3];
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

    let command = header + segment;
    put32(&mut bytes, command, 0x26);
    put32(&mut bytes, command + 4, function_starts as u32);
    put32(&mut bytes, command + 8, data_offset as u32);
    put32(&mut bytes, command + 12, 3);
    bytes[data_offset..].copy_from_slice(&[0x10, 0x20, 0]);

    let image = macho::read(&bytes).expect("valid function-starts table");
    assert_eq!(image.function_starts, vec![0x100000010, 0x100000030]);
    assert_eq!(image.function_starts_tables.len(), 1);
    assert_eq!(image.function_starts_tables[0].offset, data_offset as u64);
    assert_eq!(image.function_starts_tables[0].size, 3);
    assert!(image.function_starts_tables[0].valid);
    assert_eq!(image.function_start_records.len(), 2);
    assert_eq!(
        image.function_start_records[0].source_offset,
        data_offset as u64
    );
    assert_eq!(image.function_start_records[0].source_size, 1);
    assert!(
        image
            .function_start_records
            .iter()
            .all(|record| record.valid)
    );
}

#[test]
fn retains_function_start_outside_executable_ranges_as_invalid() {
    let header = 32;
    let segment = 72;
    let function_starts = 16;
    let data_offset = header + segment + function_starts;
    let mut bytes = vec![0u8; data_offset + 3];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, (segment + function_starts) as u32);

    put32(&mut bytes, header, 0x19);
    put32(&mut bytes, header + 4, segment as u32);
    bytes[header + 8..header + 14].copy_from_slice(b"__TEXT");
    put64(&mut bytes, header + 24, 0x100000000);
    put64(&mut bytes, header + 32, 0x40);
    put64(&mut bytes, header + 40, 0);
    let file_size = bytes.len() as u64;
    put64(&mut bytes, header + 48, file_size);
    put32(&mut bytes, header + 56, 5);
    put32(&mut bytes, header + 60, 5);

    let command = header + segment;
    put32(&mut bytes, command, 0x26);
    put32(&mut bytes, command + 4, function_starts as u32);
    put32(&mut bytes, command + 8, data_offset as u32);
    put32(&mut bytes, command + 12, 3);
    bytes[data_offset..].copy_from_slice(&[0x80, 0x01, 0]);

    let image = macho::read(&bytes).expect("function-starts table remains parseable");
    assert_eq!(image.function_starts, vec![0x100000080]);
    assert_eq!(image.function_start_records.len(), 1);
    assert!(!image.function_start_records[0].valid);
    assert!(
        image
            .function_starts_issues
            .iter()
            .any(|issue| issue.contains("outside executable"))
    );
}

#[test]
fn rejects_truncated_function_starts_uleb128() {
    let header = 32;
    let segment = 72;
    let function_starts = 16;
    let data_offset = header + segment + function_starts;
    let mut bytes = vec![0u8; data_offset + 1];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, (segment + function_starts) as u32);

    put32(&mut bytes, header, 0x19);
    put32(&mut bytes, header + 4, segment as u32);
    put64(&mut bytes, header + 24, 0x100000000);
    put64(&mut bytes, header + 32, 0x1000);
    put64(&mut bytes, header + 40, 0);
    let file_size = bytes.len() as u64;
    put64(&mut bytes, header + 48, file_size);

    let command = header + segment;
    put32(&mut bytes, command, 0x26);
    put32(&mut bytes, command + 4, function_starts as u32);
    put32(&mut bytes, command + 8, data_offset as u32);
    put32(&mut bytes, command + 12, 1);
    bytes[data_offset] = 0x80;

    assert!(matches!(
        macho::read(&bytes),
        Err(macho::Error::Malformed(_))
    ));
}

#[test]
fn decodes_data_in_code_records_and_retains_invalid_records() {
    let header = 32;
    let command = 16;
    let table = header + command;
    let mut bytes = vec![0u8; 80];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x29);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, table as u32);
    put32(&mut bytes, header + 12, 16);

    put32(&mut bytes, table, 64);
    put16(&mut bytes, table + 4, 3);
    put16(&mut bytes, table + 6, 1);
    put32(&mut bytes, table + 8, 200);
    put16(&mut bytes, table + 12, 2);
    put16(&mut bytes, table + 14, 2);

    let image = macho::read(&bytes).expect("valid data-in-code table");
    assert_eq!(image.data_in_code.len(), 2);
    assert_eq!(image.data_in_code_tables.len(), 1);
    assert_eq!(image.data_in_code_tables[0].offset, table as u64);
    assert_eq!(image.data_in_code_tables[0].size, 16);
    assert!(image.data_in_code_tables[0].valid);
    assert_eq!(image.data_in_code[0].offset, 64);
    assert_eq!(image.data_in_code[0].length, 3);
    assert_eq!(image.data_in_code[0].kind, 1);
    assert_eq!(image.data_in_code[0].kind_name, "DATA");
    assert_eq!(image.data_in_code[0].source_offset, table as u64);
    assert_eq!(image.data_in_code[0].source_size, 8);
    assert!(image.data_in_code[0].valid);
    assert!(!image.data_in_code[1].valid);
    assert_eq!(image.data_in_code_issues.len(), 1);
}

#[test]
fn retains_partial_data_in_code_record_issue() {
    let header = 32;
    let command = 16;
    let table = header + command;
    let mut bytes = vec![0u8; table + 9];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x29);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, table as u32);
    put32(&mut bytes, header + 12, 9);

    put32(&mut bytes, table, 48);
    put16(&mut bytes, table + 4, 1);
    put16(&mut bytes, table + 6, 3);

    let image = macho::read(&bytes).expect("partial data-in-code table is retained");
    assert_eq!(image.data_in_code.len(), 1);
    assert!(
        image
            .data_in_code_issues
            .iter()
            .any(|issue| issue.contains("partial record"))
    );
}

#[test]
fn decodes_code_directory_and_entitlement_ranges() {
    let header = 32;
    let command = 16;
    let signature = header + command;
    let directory = signature + 28;
    let entitlement = directory + 72;
    let mut bytes = vec![0u8; entitlement + 12];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x1d);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, signature as u32);
    put32(&mut bytes, header + 12, 112);

    put32be(&mut bytes, signature, 0xfade_0cc0);
    put32be(&mut bytes, signature + 4, 112);
    put32be(&mut bytes, signature + 8, 2);
    put32be(&mut bytes, signature + 12, 0x2);
    put32be(&mut bytes, signature + 16, 28);
    put32be(&mut bytes, signature + 20, 5);
    put32be(&mut bytes, signature + 24, 100);

    put32be(&mut bytes, directory, 0xfade_0c02);
    put32be(&mut bytes, directory + 4, 72);
    put32be(&mut bytes, directory + 8, 0x0002_0200);
    put32be(&mut bytes, directory + 12, 0x10000);
    put32be(&mut bytes, directory + 20, 52);
    bytes[directory + 37] = 2;
    put32be(&mut bytes, directory + 48, 60);
    bytes[directory + 52..directory + 56].copy_from_slice(b"app\0");
    bytes[directory + 60..directory + 65].copy_from_slice(b"TEAM\0");
    put32be(&mut bytes, entitlement, 0xfade_7171);
    put32be(&mut bytes, entitlement + 4, 12);

    let image = macho::read(&bytes).expect("valid code signature superblob");
    assert_eq!(image.code_signature_commands.len(), 1);
    assert_eq!(
        image.code_signature_commands[0].blob_offset,
        signature as u64
    );
    assert_eq!(image.code_signature_commands[0].blob_size, 112);
    assert_eq!(
        image.code_signature_commands[0].source_offset,
        header as u64
    );
    assert!(image.code_signature_commands[0].valid);
    assert_eq!(image.code_signatures.len(), 1);
    let code_signature = &image.code_signatures[0];
    assert!(code_signature.valid);
    assert_eq!(code_signature.identifier.as_deref(), Some("app"));
    assert_eq!(code_signature.team_id.as_deref(), Some("TEAM"));
    assert_eq!(code_signature.flags, Some(0x10000));
    assert_eq!(code_signature.hash_type, Some(2));
    assert_eq!(code_signature.hash_size, Some(0));
    assert_eq!(code_signature.platform, Some(0));
    assert_eq!(code_signature.signature_verification, "not_performed");
    assert_eq!(code_signature.entitlements_offset, Some(entitlement as u64));
    assert_eq!(code_signature.entitlements_size, Some(12));
    assert_eq!(image.code_signature_children.len(), 2);
    assert_eq!(image.code_signature_children[0].slot_type, 2);
    assert_eq!(image.code_signature_children[0].size, 72);
    assert!(image.code_signature_children[0].valid);
    assert!(image.code_signature_issues.is_empty());
}

#[test]
fn retains_truncated_code_signature_as_typed_issue() {
    let header = 32;
    let command = 16;
    let signature = header + command;
    let mut bytes = vec![0u8; signature + 8];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x1d);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, signature as u32);
    put32(&mut bytes, header + 12, 32);
    put32be(&mut bytes, signature, 0xfade_0cc0);
    put32be(&mut bytes, signature + 4, 32);

    let image = macho::read(&bytes).expect("truncated signature is retained");
    assert_eq!(image.code_signature_commands.len(), 1);
    assert!(!image.code_signature_commands[0].valid);
    assert_eq!(image.code_signature_commands[0].blob_size, 32);
    assert!(
        image
            .code_signature_issues
            .iter()
            .any(|issue| issue.kind == "truncated")
    );
}

#[test]
fn decodes_dyld_rebase_stream_locations() {
    let header = 32;
    let segment = 72;
    let dyld = 48;
    let stream_offset = header + segment + dyld;
    let stream = [0x11, 0x20, 0x10, 0x51, 0x00];
    let mut bytes = vec![0u8; stream_offset + stream.len() + 32];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, (segment + dyld) as u32);
    put32(&mut bytes, header, 0x19);
    put32(&mut bytes, header + 4, segment as u32);
    put64(&mut bytes, header + 24, 0x100000000);
    put64(&mut bytes, header + 32, 0x1000);
    put64(&mut bytes, header + 40, 0);
    let file_size = bytes.len() as u64;
    put64(&mut bytes, header + 48, file_size);
    let command = header + segment;
    put32(&mut bytes, command, 0x22);
    put32(&mut bytes, command + 4, dyld as u32);
    put32(&mut bytes, command + 8, stream_offset as u32);
    put32(&mut bytes, command + 12, stream.len() as u32);
    bytes[stream_offset..stream_offset + stream.len()].copy_from_slice(&stream);

    let image = macho::read(&bytes).expect("valid dyld rebase stream");
    assert_eq!(image.rebases.len(), 1);
    assert_eq!(image.rebases[0].rebase_type, 1);
    assert_eq!(image.rebases[0].segment, 0);
    assert_eq!(image.rebases[0].offset, 0x10);
    assert_eq!(image.rebases[0].source_offset, stream_offset as u64);
    assert_eq!(image.rebases[0].source_size, stream.len() as u64);
    assert!(image.rebases[0].valid);
    assert!(image.rebase_issues.is_empty());
}

#[test]
fn retains_unsupported_dyld_rebase_opcode_issue() {
    let header = 32;
    let command = 48;
    let stream_offset = header + command;
    let mut bytes = vec![0u8; stream_offset + 1];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x22);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, stream_offset as u32);
    put32(&mut bytes, header + 12, 1);
    bytes[stream_offset] = 0x90;

    let image = macho::read(&bytes).expect("unsupported rebase is retained");
    assert!(
        image
            .rebase_issues
            .iter()
            .any(|issue| issue.contains("Unsupported rebase opcode"))
    );
}

#[test]
fn decodes_32_bit_encryption_info_range() {
    let header = 28;
    let command = 20;
    let mut bytes = vec![0u8; 80];
    put32(&mut bytes, 0, 0xfeedface);
    put32(&mut bytes, 4, 7);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x21);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 40);
    put32(&mut bytes, header + 12, 16);
    put32(&mut bytes, header + 16, 1);

    let image = macho::read(&bytes).expect("valid 32-bit encryption info");
    assert_eq!(image.encryption_info.len(), 1);
    assert_eq!(image.encryption_info[0].offset, 40);
    assert_eq!(image.encryption_info[0].size, 16);
    assert_eq!(image.encryption_info[0].crypt_id, 1);
    assert!(image.encryption_info[0].valid);
    assert_eq!(image.encryption_info[0].state, "encrypted");
    assert_eq!(image.encryption_info[0].source_offset, header as u64);
    assert_eq!(image.encryption_info[0].source_size, command as u64);
    assert!(image.encryption_issues.is_empty());
}

#[test]
fn decodes_64_bit_encryption_info_and_retains_out_of_file_range() {
    let header = 32;
    let command = 24;
    let mut bytes = vec![0u8; 80];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x2c);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 72);
    put32(&mut bytes, header + 12, 32);
    put32(&mut bytes, header + 16, 2);

    let image = macho::read(&bytes).expect("out-of-file encryption range is retained");
    assert_eq!(image.encryption_info.len(), 1);
    assert_eq!(image.encryption_info[0].crypt_id, 2);
    assert!(!image.encryption_info[0].valid);
    assert_eq!(image.encryption_info[0].state, "unknown");
    assert_eq!(image.encryption_info[0].source_offset, header as u64);
    assert_eq!(image.encryption_info[0].source_size, command as u64);
    assert!(
        image
            .encryption_issues
            .iter()
            .any(|issue| issue.contains("exceeds"))
    );
}

#[test]
fn classifies_zero_size_encryption_info_as_unencrypted() {
    let header = 28;
    let command = 20;
    let mut bytes = vec![0u8; 64];
    put32(&mut bytes, 0, 0xfeedface);
    put32(&mut bytes, 4, 7);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x21);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 40);
    put32(&mut bytes, header + 12, 0);
    put32(&mut bytes, header + 16, 0);

    let image = macho::read(&bytes).expect("zero-size encryption info is valid metadata");
    let encryption = &image.encryption_info[0];
    assert!(encryption.valid);
    assert_eq!(encryption.state, "unencrypted");
    assert_eq!(encryption.offset, 40);
    assert_eq!(encryption.size, 0);
    assert!(image.encryption_issues.is_empty());
}

#[test]
fn classifies_zero_size_64_bit_encryption_info_as_unencrypted() {
    let header = 32;
    let command = 24;
    let mut bytes = vec![0u8; 72];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x2c);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 48);
    put32(&mut bytes, header + 12, 0);
    put32(&mut bytes, header + 16, 0);

    let image = macho::read(&bytes).expect("zero-size 64-bit encryption info is valid metadata");
    let encryption = &image.encryption_info[0];
    assert!(encryption.valid);
    assert_eq!(encryption.state, "unencrypted");
    assert_eq!(encryption.source_offset, header as u64);
    assert_eq!(encryption.source_size, command as u64);
    assert!(image.encryption_issues.is_empty());
}

#[test]
fn rejects_truncated_32_bit_encryption_info_command() {
    let header = 28;
    let mut bytes = vec![0u8; 64];
    put32(&mut bytes, 0, 0xfeedface);
    put32(&mut bytes, 4, 7);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, 16);
    put32(&mut bytes, header, 0x21);
    put32(&mut bytes, header + 4, 16);

    let error = macho::read(&bytes).expect_err("truncated encryption command must fail");
    assert!(
        error
            .to_string()
            .contains("Truncated encryption-info command")
    );
}

#[test]
fn rejects_truncated_64_bit_encryption_info_command() {
    let header = 32;
    let mut bytes = vec![0u8; 64];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, 16);
    put32(&mut bytes, header, 0x2c);
    put32(&mut bytes, header + 4, 16);

    let error = macho::read(&bytes).expect_err("truncated encryption command must fail");
    assert!(
        error
            .to_string()
            .contains("Truncated encryption-info command")
    );
}

#[test]
fn connects_indirect_stub_slots_to_imported_symbols() {
    let header = 32;
    let segment = 152;
    let dysymtab = 80;
    let symtab_size = 24;
    let symbol_offset = header + segment + dysymtab + symtab_size;
    let string_offset = symbol_offset + 16;
    let indirect_offset = string_offset + 6;
    let mut bytes = vec![0u8; 512];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 3);
    put32(&mut bytes, 20, (segment + dysymtab + symtab_size) as u32);

    let segment_at = header;
    put32(&mut bytes, segment_at, 0x19);
    put32(&mut bytes, segment_at + 4, segment as u32);
    bytes[segment_at + 8..segment_at + 14].copy_from_slice(b"__TEXT");
    put64(&mut bytes, segment_at + 24, 0x100000000);
    put64(&mut bytes, segment_at + 32, 0x1000);
    put64(&mut bytes, segment_at + 40, 0);
    put64(&mut bytes, segment_at + 48, 512);
    put32(&mut bytes, segment_at + 56, 5);
    put32(&mut bytes, segment_at + 60, 5);
    put32(&mut bytes, segment_at + 64, 1);
    let section = segment_at + 72;
    bytes[section..section + 8].copy_from_slice(b"__stubs\0");
    bytes[section + 16..section + 22].copy_from_slice(b"__TEXT");
    put64(&mut bytes, section + 32, 0x100000100);
    put64(&mut bytes, section + 40, 8);
    put32(&mut bytes, section + 48, 400);
    put32(&mut bytes, section + 64, 0x80000008);
    put32(&mut bytes, section + 68, 0);
    put32(&mut bytes, section + 72, 8);

    let dysym = segment_at + segment;
    put32(&mut bytes, dysym, 0xb);
    put32(&mut bytes, dysym + 4, dysymtab as u32);
    put32(&mut bytes, dysym + 56, indirect_offset as u32);
    put32(&mut bytes, dysym + 60, 1);
    let symtab = dysym + dysymtab;
    put32(&mut bytes, symtab, 2);
    put32(&mut bytes, symtab + 4, 24);
    put32(&mut bytes, symtab + 8, symbol_offset as u32);
    put32(&mut bytes, symtab + 12, 1);
    put32(&mut bytes, symtab + 16, string_offset as u32);
    put32(&mut bytes, symtab + 20, 6);
    put32(&mut bytes, symbol_offset, 1);
    bytes[symbol_offset + 4] = 0x01;
    put64(&mut bytes, symbol_offset + 8, 0);
    bytes[string_offset..string_offset + 6].copy_from_slice(b"\0_imp\0");
    put32(&mut bytes, indirect_offset, 0);

    let image = macho::read(&bytes).expect("valid indirect symbol table");
    assert_eq!(image.indirect_symbols.len(), 1);
    assert_eq!(image.indirect_symbols[0].symbol.as_deref(), Some("_imp"));
    assert_eq!(image.indirect_symbols[0].source_offset, 400);
    assert_eq!(image.indirect_symbols[0].raw_value, 0);
    assert_eq!(image.indirect_symbols[0].classification, None);
    assert!(image.indirect_symbols[0].valid);
    assert_eq!(
        image
            .dysymtab
            .as_ref()
            .map(|table| table.indirect_symbol_count),
        Some(1)
    );
    let dysymtab = image.dysymtab.as_ref().expect("dysymtab metadata");
    assert_eq!(dysymtab.indirect_source_offset, indirect_offset as u64);
    assert_eq!(dysymtab.indirect_source_size, 4);
    let indirect_table = dysymtab
        .tables
        .iter()
        .find(|table| table.kind == "indirect_symbols")
        .expect("indirect table descriptor");
    assert_eq!(indirect_table.offset, indirect_offset as u64);
    assert_eq!(indirect_table.count, 1);
    assert_eq!(indirect_table.entry_size, 4);
    assert!(indirect_table.valid);
    assert!(image.indirect_symbol_issues.is_empty());
}

#[test]
fn retains_malformed_dysymtab_auxiliary_ranges() {
    let header = 32;
    let command_size = 80;
    let mut bytes = vec![0u8; header + command_size];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command_size as u32);
    put32(&mut bytes, header, 0xb);
    put32(&mut bytes, header + 4, command_size as u32);
    put32(&mut bytes, header + 64, 256);
    put32(&mut bytes, header + 68, 1);

    let image = macho::read(&bytes).expect("malformed auxiliary range is retained");
    let dysymtab = image.dysymtab.as_ref().expect("dysymtab metadata");
    let relocations = dysymtab
        .tables
        .iter()
        .find(|table| table.kind == "external_relocations")
        .expect("external relocation descriptor");
    assert_eq!(relocations.offset, 256);
    assert_eq!(relocations.count, 1);
    assert_eq!(relocations.entry_size, 8);
    assert!(!relocations.valid);
    assert!(!dysymtab.valid);
    assert!(
        image
            .indirect_symbol_issues
            .iter()
            .any(|issue| issue.contains("external_relocations"))
    );
}

#[test]
fn decodes_arm64e_chained_pointer_auth_metadata() {
    let header = 32;
    let segment = 72;
    let fixups = 16;
    let data = header + segment + fixups;
    let starts = data + 28;
    let info = starts + 8;
    let imports = info + 24;
    let symbols = imports + 4;
    let mut bytes = vec![0u8; 512];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, (segment + fixups) as u32);
    put32(&mut bytes, header, 0x19);
    put32(&mut bytes, header + 4, segment as u32);
    put64(&mut bytes, header + 24, 0x100000100);
    put64(&mut bytes, header + 32, 0x1000);
    put64(&mut bytes, header + 40, 0x100);
    put64(&mut bytes, header + 48, 0x100);
    put32(&mut bytes, header + 56, 5);
    put32(&mut bytes, header + 60, 5);

    let command = header + segment;
    put32(&mut bytes, command, 0x80000034);
    put32(&mut bytes, command + 4, fixups as u32);
    put32(&mut bytes, command + 8, data as u32);
    put32(&mut bytes, command + 12, 71);
    put32(&mut bytes, data, 0);
    put32(&mut bytes, data + 4, 28);
    put32(&mut bytes, data + 8, 60);
    put32(&mut bytes, data + 12, 64);
    put32(&mut bytes, data + 16, 1);
    put32(&mut bytes, data + 20, 1);
    put32(&mut bytes, data + 24, 0);
    put32(&mut bytes, starts, 1);
    put32(&mut bytes, starts + 4, 8);
    put32(&mut bytes, info, 24);
    put16(&mut bytes, info + 4, 0x1000);
    put16(&mut bytes, info + 6, 1);
    put64(&mut bytes, info + 8, 0x100000100);
    put32(&mut bytes, info + 16, 0);
    put16(&mut bytes, info + 20, 1);
    put16(&mut bytes, info + 22, 0);
    put32(&mut bytes, imports, 0);
    bytes[symbols..symbols + 1].copy_from_slice(b"\0");
    let raw = 0x1234 | (0x55 << 32) | (1 << 48) | (2 << 49) | (1u64 << 63);
    put64(&mut bytes, 0x100, raw);

    let image = macho::read(&bytes).expect("valid arm64e chained pointer");
    assert_eq!(image.chained_pointers.len(), 1);
    let pointer = &image.chained_pointers[0];
    assert_eq!(pointer.target, Some(0x100000100 + 0x1234));
    assert_eq!(pointer.diversity, Some(0x55));
    assert_eq!(pointer.address_diversity, Some(true));
    assert_eq!(pointer.key, Some(2));
    assert_eq!(pointer.authenticated, Some(true));
}

#[test]
fn preserves_lc_note_owner_and_bounded_range() {
    let header = 32;
    let command = 40;
    let mut bytes = vec![0u8; 128];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);

    put32(&mut bytes, header, 0x31);
    put32(&mut bytes, header + 4, command as u32);
    bytes[header + 8..header + 24].copy_from_slice(b"TEST\0owner-byte\0");
    put64(&mut bytes, header + 24, 80);
    put64(&mut bytes, header + 32, 16);
    bytes[80..96].copy_from_slice(b"opaque-note-data");

    let image = macho::read(&bytes).expect("valid LC_NOTE command");
    assert_eq!(image.notes.len(), 1);
    let note = &image.notes[0];
    assert_eq!(note.owner, "TEST");
    assert_eq!(note.owner_bytes, b"TEST\0owner-byte\0");
    assert_eq!(note.offset, 80);
    assert_eq!(note.size, 16);
    assert_eq!(note.source_offset, header as u64);
    assert_eq!(note.source_size, command as u64);
    assert!(note.aligned);
    assert!(note.valid);
    assert!(note.owner_utf8_valid);
    assert!(image.note_issues.is_empty());
}

#[test]
fn retains_invalid_utf8_lc_note_owner_as_raw_bytes() {
    let header = 32;
    let command = 40;
    let mut bytes = vec![0u8; 128];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);

    put32(&mut bytes, header, 0x31);
    put32(&mut bytes, header + 4, command as u32);
    bytes[header + 8..header + 24].fill(0);
    bytes[header + 8..header + 11].copy_from_slice(&[0xff, b'N', 0]);
    put64(&mut bytes, header + 24, 80);
    put64(&mut bytes, header + 32, 4);
    bytes[80..84].copy_from_slice(b"data");

    let image = macho::read(&bytes).expect("invalid owner encoding is recoverable");
    let note = &image.notes[0];
    assert!(!note.owner_utf8_valid);
    assert_eq!(&note.owner_bytes[..3], &[0xff, b'N', 0]);
    assert_eq!(note.owner, "�N");
    assert!(note.valid);
    assert!(
        image
            .note_issues
            .iter()
            .any(|issue| issue.contains("not valid UTF-8"))
    );
}

#[test]
fn records_lc_note_alignment_and_out_of_file_range() {
    let header = 32;
    let command = 40;
    let mut bytes = vec![0u8; 128];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);

    put32(&mut bytes, header, 0x31);
    put32(&mut bytes, header + 4, command as u32);
    bytes[header + 8..header + 24].copy_from_slice(b"ALIGNMENT\0\0\0\0\0\0\0");
    put64(&mut bytes, header + 24, 65);
    put64(&mut bytes, header + 32, 80);

    let image = macho::read(&bytes).expect("LC_NOTE range facts are recoverable");
    let note = &image.notes[0];
    assert!(!note.aligned);
    assert!(!note.valid);
    assert!(
        image
            .note_issues
            .iter()
            .any(|issue| issue.contains("aligned"))
    );
    assert!(
        image
            .note_issues
            .iter()
            .any(|issue| issue.contains("exceeds"))
    );
}

#[test]
fn rejects_truncated_lc_note_command() {
    let header = 32;
    let command = 32;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x31);
    put32(&mut bytes, header + 4, command as u32);

    assert!(matches!(
        macho::read(&bytes),
        Err(macho::Error::Malformed("Truncated LC_NOTE command"))
    ));
}

#[test]
fn decodes_dylinker_paths_with_command_provenance() {
    let header = 32;
    let command = 32;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0xe);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 12);
    bytes[header + 12..header + 28].copy_from_slice(b"/usr/lib/dyld\0\0\0");

    let image = macho::read(&bytes).expect("dylinker path is decoded");
    assert_eq!(image.dylinkers.len(), 1);
    let dylinker = &image.dylinkers[0];
    assert_eq!(dylinker.value.as_deref(), Some("/usr/lib/dyld"));
    assert_eq!(dylinker.raw_bytes, b"/usr/lib/dyld\0");
    assert_eq!(dylinker.command_offset, header as u64);
    assert_eq!(dylinker.command_size, command as u64);
    assert_eq!(dylinker.string_offset, Some(12));
    assert!(image.path_issues.is_empty());
}

#[test]
fn retains_unterminated_dylinker_path_as_invalid_fact() {
    let header = 32;
    let command = 24;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0xf);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 12);
    bytes[header + 12..header + 24].copy_from_slice(b"dyldpathXXXX");

    let image = macho::read(&bytes).expect("unterminated dylinker remains recoverable");
    assert_eq!(image.dylinkers[0].value.as_deref(), Some("dyldpathXXXX"));
    assert_eq!(image.dylinkers[0].raw_bytes, b"dyldpathXXXX");
    assert!(
        image
            .path_issues
            .iter()
            .any(|issue| issue.contains("unterminated"))
    );
}

#[test]
fn retains_invalid_utf8_dylinker_path_bytes() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0xe);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 12);
    bytes[header + 12..header + 16].copy_from_slice(&[0xff, b'd', 0, 0]);

    let image = macho::read(&bytes).expect("invalid UTF-8 dylinker remains observable");
    let dylinker = &image.dylinkers[0];
    assert_eq!(dylinker.raw_bytes, vec![0xff, b'd', 0]);
    assert!(dylinker.value.is_none());
    assert!(!dylinker.utf8_valid);
    assert!(!dylinker.valid);
    assert!(
        image
            .path_issues
            .iter()
            .any(|issue| issue.contains("not valid UTF-8"))
    );
}

#[test]
fn records_lc_note_range_overflow() {
    let header = 32;
    let command = 40;
    let mut bytes = vec![0u8; 128];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x31);
    put32(&mut bytes, header + 4, command as u32);
    put64(&mut bytes, header + 24, u64::MAX);
    put64(&mut bytes, header + 32, 1);

    let image = macho::read(&bytes).expect("overflow is a recoverable LC_NOTE fact");
    assert!(!image.notes[0].valid);
    assert!(
        image
            .note_issues
            .iter()
            .any(|issue| issue.contains("overflowed"))
    );
}

#[test]
fn maps_lc_main_to_a_file_backed_vm_address() {
    let header = 32;
    let segment = 72;
    let main = 24;
    let mut bytes = vec![0u8; 512];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x01000007);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, (segment + main) as u32);
    put32(&mut bytes, header, 0x19);
    put32(&mut bytes, header + 4, segment as u32);
    put64(&mut bytes, header + 24, 0x1000);
    put64(&mut bytes, header + 32, 0x1000);
    put64(&mut bytes, header + 40, 0x100);
    put64(&mut bytes, header + 48, 0x100);
    let main_at = header + segment;
    put32(&mut bytes, main_at, 0x80000028);
    put32(&mut bytes, main_at + 4, main as u32);
    put64(&mut bytes, main_at + 8, 0x120);
    put64(&mut bytes, main_at + 16, 0x2000);

    let image = macho::read(&bytes).expect("valid LC_MAIN mapping");
    let entrypoint = image.entrypoint.expect("entrypoint");
    assert_eq!(entrypoint.file_offset, 0x120);
    assert_eq!(entrypoint.vm_address, Some(0x1020));
    assert_eq!(entrypoint.stack_size, 0x2000);
    assert_eq!(entrypoint.source_offset, (header + segment) as u64);
    assert_eq!(entrypoint.source_size, main as u64);
    assert!(entrypoint.valid);
}

#[test]
fn rejects_truncated_lc_main_command() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x8000_0028);
    put32(&mut bytes, header + 4, command as u32);

    assert!(matches!(
        macho::read(&bytes),
        Err(macho::Error::Malformed("Truncated LC_MAIN command"))
    ));
}

#[test]
fn decodes_x86_64_unixthread_pc_without_execution() {
    let header = 32;
    let thread = 184;
    let mut bytes = vec![0u8; header + thread];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x01000007);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, thread as u32);
    put32(&mut bytes, header, 0x5);
    put32(&mut bytes, header + 4, thread as u32);
    put32(&mut bytes, header + 8, 4);
    put32(&mut bytes, header + 12, 42);
    put64(&mut bytes, header + 16 + 16 * 8, 0x1234_5678);

    let image = macho::read(&bytes).expect("valid x86_64 LC_UNIXTHREAD");
    assert_eq!(image.unix_threads.len(), 1);
    assert_eq!(image.unix_threads[0].pc, Some(0x1234_5678));
    assert!(image.unix_threads[0].supported);
    assert!(image.unix_threads[0].valid);
}

#[test]
fn preserves_truncated_unixthread_as_an_unknown_pc() {
    let header = 32;
    let thread = 24;
    let mut bytes = vec![0u8; header + thread];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, thread as u32);
    put32(&mut bytes, header, 0x5);
    put32(&mut bytes, header + 4, thread as u32);
    put32(&mut bytes, header + 8, 6);
    put32(&mut bytes, header + 12, 34);

    let image = macho::read(&bytes).expect("truncated thread state remains observable");
    assert_eq!(image.unix_threads[0].pc, None);
    assert!(!image.unix_threads[0].valid);
    assert!(
        image
            .unix_thread_issues
            .iter()
            .any(|issue| issue.contains("truncated"))
    );
}

#[test]
fn decodes_fileset_entry_and_maps_its_file_offset() {
    let header = 32;
    let segment = 72;
    let fileset = 40;
    let command = header + segment;
    let id_offset = command + 32;
    let mut bytes = vec![0u8; 512];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, (segment + fileset) as u32);
    put32(&mut bytes, header, 0x19);
    put32(&mut bytes, header + 4, segment as u32);
    put64(&mut bytes, header + 24, 0x1000);
    put64(&mut bytes, header + 32, 0x1000);
    put64(&mut bytes, header + 40, 0x100);
    put64(&mut bytes, header + 48, 0x100);
    put32(&mut bytes, command, 0x80000035);
    put32(&mut bytes, command + 4, fileset as u32);
    put64(&mut bytes, command + 8, 0x1020);
    put64(&mut bytes, command + 16, 0x120);
    put32(&mut bytes, command + 24, 32);
    put32(&mut bytes, command + 28, 0);
    bytes[id_offset..id_offset + 6].copy_from_slice(b"child\0");

    let image = macho::read(&bytes).expect("valid fileset entry");
    let entry = &image.fileset_entries[0];
    assert_eq!(entry.entry_id.as_deref(), Some("child"));
    assert_eq!(entry.entry_id_bytes, b"child");
    assert!(entry.entry_id_utf8_valid);
    assert_eq!(entry.entry_id_source_offset, Some(id_offset as u64));
    assert_eq!(entry.entry_id_source_size, 5);
    assert_eq!(entry.source_offset, command as u64);
    assert_eq!(entry.source_size, fileset as u64);
    assert_eq!(entry.file_offset, Some(0x120));
    assert_eq!(entry.vm_address, Some(0x1020));
    assert_eq!(entry.mapped_vm_address, Some(0x1020));
    assert!(entry.valid);
}

#[test]
fn retains_invalid_fileset_entry_id_bytes() {
    let header = 32;
    let fileset = 40;
    let mut bytes = vec![0u8; header + fileset];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, fileset as u32);
    put32(&mut bytes, header, 0x8000_0035);
    put32(&mut bytes, header + 4, fileset as u32);
    put64(&mut bytes, header + 8, 0x1000);
    put64(&mut bytes, header + 16, 0x20);
    put32(&mut bytes, header + 24, 32);
    bytes[header + 32..header + 36].copy_from_slice(&[0xff, b'X', 0, 0]);

    let image = macho::read(&bytes).expect("invalid fileset ID remains observable");
    let entry = &image.fileset_entries[0];
    assert!(!entry.entry_id_utf8_valid);
    assert_eq!(entry.entry_id_bytes, vec![0xff, b'X']);
    assert_eq!(entry.entry_id_source_offset, Some((header + 32) as u64));
    assert_eq!(entry.entry_id_source_size, 2);
    assert_eq!(entry.entry_id, Some("�X".into()));
    assert!(
        image
            .fileset_entry_issues
            .iter()
            .any(|issue| issue.contains("not valid UTF-8"))
    );
}

#[test]
fn records_out_of_file_and_truncated_fileset_entries() {
    let header = 32;
    let fileset = 40;
    let mut bytes = vec![0u8; header + fileset * 2];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, (fileset + 24) as u32);
    put32(&mut bytes, header, 0x80000035);
    put32(&mut bytes, header + 4, fileset as u32);
    put64(&mut bytes, header + 16, 0x1000);
    put32(&mut bytes, header + 24, 32);
    bytes[header + 32..header + 38].copy_from_slice(b"bad\0\0\0");
    let truncated = header + fileset;
    put32(&mut bytes, truncated, 0x80000035);
    put32(&mut bytes, truncated + 4, 24);

    let image = macho::read(&bytes).expect("fileset boundary facts are recoverable");
    assert_eq!(image.fileset_entries.len(), 2);
    assert!(!image.fileset_entries[0].valid);
    assert!(!image.fileset_entries[1].valid);
    assert!(
        image
            .fileset_entry_issues
            .iter()
            .any(|issue| issue.contains("Truncated"))
    );
}

#[test]
fn decodes_build_version_tools_and_source_ranges() {
    let header = 32;
    let command = 40;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x32);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 6);
    put32(&mut bytes, header + 12, (14 << 16) | (2 << 8));
    put32(&mut bytes, header + 16, (15 << 16) | (1 << 8));
    put32(&mut bytes, header + 20, 2);
    put32(&mut bytes, header + 24, 1);
    put32(&mut bytes, header + 28, (15 << 16) | (0 << 8) | 3);
    put32(&mut bytes, header + 32, 3);
    put32(&mut bytes, header + 36, (12 << 16) | (4 << 8));

    let image = macho::read(&bytes).expect("valid LC_BUILD_VERSION command");
    assert_eq!(image.build_metadata[0].platform, Some(6));
    assert_eq!(
        image.build_metadata[0].platform_name.as_deref(),
        Some("MACCATALYST")
    );
    assert_eq!(
        image.build_metadata[0].min_os_raw,
        Some((14 << 16) | (2 << 8))
    );
    assert_eq!(image.build_metadata[0].sdk_raw, Some((15 << 16) | (1 << 8)));
    assert_eq!(image.build_metadata[0].source_offset, header as u64);
    assert_eq!(image.build_metadata[0].source_size, command as u64);
    assert_eq!(image.build_tools.len(), 2);
    assert_eq!(image.build_tools[0].tool, 1);
    assert_eq!(image.build_tools[0].tool_name, "CLANG");
    assert_eq!(image.build_tools[0].version, "15.0.3");
    assert_eq!(image.build_tools[0].version_raw, (15 << 16) | 3);
    assert_eq!(image.build_tools[1].tool, 3);
    assert_eq!(image.build_tools[1].tool_name, "LD");
    assert!(image.build_metadata_issues.is_empty());
}

#[test]
fn decodes_newer_build_platform_and_preserves_unknown_tool_values() {
    let header = 28;
    let command = 32;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedface);
    put32(&mut bytes, 4, 7);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x32);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 15);
    put32(&mut bytes, header + 12, 0x01020304);
    put32(&mut bytes, header + 16, 0x05060708);
    put32(&mut bytes, header + 20, 1);
    put32(&mut bytes, header + 24, 0xdead);
    put32(&mut bytes, header + 28, 0x090a0b0c);

    let image = macho::read(&bytes).expect("32-bit build metadata is decoded");
    let metadata = &image.build_metadata[0];
    assert_eq!(metadata.command_kind, "LC_BUILD_VERSION");
    assert_eq!(metadata.platform, Some(15));
    assert_eq!(metadata.platform_name.as_deref(), Some("MACOS_EXCLAVECORE"));
    assert_eq!(metadata.min_os_raw, Some(0x01020304));
    assert_eq!(metadata.sdk_raw, Some(0x05060708));
    assert_eq!(metadata.source_offset, header as u64);
    assert_eq!(metadata.source_size, command as u64);
    assert_eq!(image.build_tools[0].tool, 0xdead);
    assert_eq!(image.build_tools[0].version_raw, 0x090a0b0c);
}

#[test]
fn records_truncated_build_version_tool_table() {
    let header = 32;
    let command = 32;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x32);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 6);
    put32(&mut bytes, header + 12, 1 << 16);
    put32(&mut bytes, header + 16, 1 << 16);
    put32(&mut bytes, header + 20, 2);
    put32(&mut bytes, header + 24, 1);
    put32(&mut bytes, header + 28, 1 << 16);

    let image = macho::read(&bytes).expect("truncated tool table remains bounded");
    assert_eq!(image.build_tools.len(), 1);
    assert!(
        image
            .build_metadata_issues
            .iter()
            .any(|issue| issue.contains("declares 2 tools"))
    );
}

#[test]
fn preserves_minimum_os_command_identity_and_raw_versions() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command * 2];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, (command * 2) as u32);

    put32(&mut bytes, header, 0x24);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 0x0f020000);
    put32(&mut bytes, header + 12, 0x10010000);

    let second = header + command;
    put32(&mut bytes, second, 0x25);
    put32(&mut bytes, second + 4, command as u32);
    put32(&mut bytes, second + 8, 0x0e030000);
    put32(&mut bytes, second + 12, 0x0f010000);

    let image = macho::read(&bytes).expect("minimum OS commands are decoded");
    assert_eq!(image.build_metadata.len(), 2);
    assert_eq!(
        image.build_metadata[0].command_kind,
        "LC_VERSION_MIN_MACOSX"
    );
    assert_eq!(image.build_metadata[0].min_os_raw, Some(0x0f020000));
    assert_eq!(image.build_metadata[0].sdk_raw, Some(0x10010000));
    assert_eq!(
        image.build_metadata[0].platform_name.as_deref(),
        Some("MACOSX")
    );
    assert_eq!(
        image.build_metadata[1].command_kind,
        "LC_VERSION_MIN_IPHONEOS"
    );
    assert_eq!(image.build_metadata[1].min_os_raw, Some(0x0e030000));
    assert_eq!(image.build_metadata[1].sdk_raw, Some(0x0f010000));
    assert_eq!(
        image.build_metadata[1].platform_name.as_deref(),
        Some("IPHONEOS")
    );
}

#[test]
fn infers_legacy_simulator_platforms_from_cpu_type() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command * 2];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x01000007);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, (command * 2) as u32);

    put32(&mut bytes, header, 0x25);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 0x0f000000);
    put32(&mut bytes, header + 12, 0x10000000);

    let second = header + command;
    put32(&mut bytes, second, 0x2f);
    put32(&mut bytes, second + 4, command as u32);
    put32(&mut bytes, second + 8, 0x0f000000);
    put32(&mut bytes, second + 12, 0x10000000);

    let image = macho::read(&bytes).expect("legacy simulator commands are decoded");
    assert_eq!(image.build_metadata[0].platform, Some(7));
    assert_eq!(
        image.build_metadata[0].platform_name.as_deref(),
        Some("IOSSIMULATOR")
    );
    assert_eq!(image.build_metadata[1].platform, Some(8));
    assert_eq!(
        image.build_metadata[1].platform_name.as_deref(),
        Some("TVOSSIMULATOR")
    );
}

#[test]
fn decodes_rpath_and_dyld_environment_path_records() {
    let header = 32;
    let rpath = 8 + 4 + 12;
    let environment = 8 + 4 + 12;
    let mut bytes = vec![0u8; header + rpath + environment];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 2);
    put32(&mut bytes, 16, 2);
    put32(&mut bytes, 20, (rpath + environment) as u32);
    put32(&mut bytes, header, 0x8000001c);
    put32(&mut bytes, header + 4, rpath as u32);
    put32(&mut bytes, header + 8, 12);
    bytes[header + 12..header + 21].copy_from_slice(b"@loader/\0");
    let environment_at = header + rpath;
    put32(&mut bytes, environment_at, 0x27);
    put32(&mut bytes, environment_at + 4, environment as u32);
    put32(&mut bytes, environment_at + 8, 12);
    bytes[environment_at + 12..environment_at + 21].copy_from_slice(b"DYLD_X=1\0");

    let image = macho::read(&bytes).expect("valid path commands");
    assert_eq!(image.rpaths, vec!["@loader/"]);
    assert_eq!(image.rpath_records[0].raw_bytes, b"@loader/\0");
    assert_eq!(image.rpath_records[0].command_offset, header as u64);
    assert_eq!(
        image.rpath_records[0].string_source_offset,
        Some((header + 12) as u64)
    );
    assert_eq!(image.rpath_records[0].string_source_size, 9);
    assert!(image.rpath_records[0].valid);
    assert_eq!(image.dyld_environment[0].value.as_deref(), Some("DYLD_X=1"));
    assert_eq!(image.dyld_environment[0].string_offset, Some(12));
    assert!(image.path_issues.is_empty());
}

#[test]
fn preserves_unterminated_path_string_issue() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x8000001c);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 12);
    bytes[header + 12..header + 16].copy_from_slice(b"rpth");

    let image = macho::read(&bytes).expect("unterminated path remains observable");
    assert_eq!(image.rpath_records[0].value.as_deref(), Some("rpth"));
    assert_eq!(image.rpath_records[0].raw_bytes, b"rpth");
    assert_eq!(
        image.rpath_records[0].string_source_offset,
        Some((header + 12) as u64)
    );
    assert_eq!(image.rpath_records[0].string_source_size, 4);
    assert!(!image.rpath_records[0].valid);
    assert!(
        image
            .path_issues
            .iter()
            .any(|issue| issue.contains("unterminated"))
    );
}

#[test]
fn decodes_typed_dylib_load_variants() {
    let header = 32;
    let command = 40;
    let mut bytes = vec![0u8; header + command * 4];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 4);
    put32(&mut bytes, 16, 4);
    put32(&mut bytes, 20, (command * 4) as u32);
    let kinds = [
        (0xc, "libload"),
        (0x80000018, "libweak"),
        (0x8000001f, "libreexport"),
        (0x80000023, "libupward"),
    ];
    for (index, (kind, name)) in kinds.into_iter().enumerate() {
        let offset = header + index * command;
        put32(&mut bytes, offset, kind);
        put32(&mut bytes, offset + 4, command as u32);
        put32(&mut bytes, offset + 8, 24);
        put32(&mut bytes, offset + 12, 1234 + index as u32);
        put32(&mut bytes, offset + 16, (15 << 16) | index as u32);
        put32(&mut bytes, offset + 20, 1 << 16);
        let name_end = offset + 24 + name.len();
        bytes[offset + 24..name_end].copy_from_slice(name.as_bytes());
    }

    let image = macho::read(&bytes).expect("valid dylib load variants");
    assert_eq!(image.dylibs.len(), 4);
    assert_eq!(image.dylibs[0].kind, "load");
    assert_eq!(image.dylibs[1].kind, "weak");
    assert_eq!(image.dylibs[2].kind, "reexport");
    assert_eq!(image.dylibs[3].kind, "upward");
    assert_eq!(image.dylibs[0].name.as_deref(), Some("libload"));
    assert_eq!(image.dylibs[0].timestamp, Some(1234));
    assert_eq!(image.dylibs[0].current_version.as_deref(), Some("15.0.0"));
    assert_eq!(
        image.dylibs[0].compatibility_version.as_deref(),
        Some("1.0.0")
    );
    assert_eq!(image.dylibs[0].name_bytes, b"libload\0");
    assert!(image.dylibs[0].name_utf8_valid);
    assert_eq!(
        image.dylibs[0].name_source_offset,
        Some((header + 24) as u64)
    );
    assert_eq!(image.dylibs[0].name_source_size, 7);
    assert_eq!(image.dependencies.len(), 4);
}

#[test]
fn decodes_dylib_use_command_flags() {
    let header = 32;
    let command = 40;
    let mut bytes = vec![0u8; header + command * 3];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 3);
    put32(&mut bytes, 16, 3);
    put32(&mut bytes, 20, (command * 3) as u32);

    let commands = [
        (0xc, 0x8, "libdelay"),
        (0xc, 0x1 | 0x4, "libweakup"),
        (0xc, 0x2, "libreexport"),
    ];
    for (index, (kind, flags, name)) in commands.into_iter().enumerate() {
        let offset = header + index * command;
        put32(&mut bytes, offset, kind);
        put32(&mut bytes, offset + 4, command as u32);
        put32(&mut bytes, offset + 8, 28);
        put32(&mut bytes, offset + 12, 0x1a74_1800);
        put32(&mut bytes, offset + 16, 1 << 16);
        put32(&mut bytes, offset + 20, 2 << 16);
        put32(&mut bytes, offset + 24, flags);
        bytes[offset + 28..offset + 28 + name.len()].copy_from_slice(name.as_bytes());
    }

    let image = macho::read(&bytes).expect("valid dylib_use_command records");
    assert_eq!(image.dependencies.len(), 3);
    assert_eq!(image.dependencies[0].encoding, "dylib_use_command");
    assert!(!image.dependencies[0].weak);
    assert!(!image.dependencies[0].upward);
    assert!(!image.dependencies[0].reexport);
    assert!(image.dependencies[0].delayed_init);
    assert!(image.dependencies[1].weak);
    assert!(image.dependencies[1].upward);
    assert!(!image.dependencies[1].reexport);
    assert!(image.dependencies[2].reexport);
    assert_eq!(image.dylibs[2].name.as_deref(), Some("libreexport"));
}

#[test]
fn retains_invalid_dylib_name_bytes_and_issue() {
    let header = 32;
    let command = 32;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0xc);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 24);
    bytes[header + 24..header + 28].copy_from_slice(&[0xff, b'X', 0, 0]);

    let image = macho::read(&bytes).expect("invalid dylib name remains observable");
    let dylib = &image.dylibs[0];
    assert!(!dylib.name_utf8_valid);
    assert_eq!(dylib.name_bytes, vec![0xff, b'X', 0]);
    assert_eq!(dylib.name, Some("�X".into()));
    assert_eq!(dylib.name_source_offset, Some((header + 24) as u64));
    assert_eq!(dylib.name_source_size, 2);
    assert!(
        image
            .dylib_issues
            .iter()
            .any(|issue| issue.contains("not valid UTF-8"))
    );
}

#[test]
fn records_malformed_dylib_name_command() {
    let header = 32;
    let command = 24;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0xc);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 24);

    let image = macho::read(&bytes).expect("malformed dylib remains observable");
    assert_eq!(image.dylibs.len(), 1);
    assert!(image.dylibs[0].name.is_none());
    assert!(!image.dylibs[0].valid);
    assert!(
        image
            .dylib_issues
            .iter()
            .any(|issue| issue.contains("outside"))
    );
}

#[test]
fn preserves_unresolved_32_bit_nlist_string_index() {
    let header = 28;
    let command = 24;
    let symbol_offset = header + command;
    let string_offset = symbol_offset + 12;
    let mut bytes = vec![0u8; string_offset + 4];
    put32(&mut bytes, 0, 0xfeedface);
    put32(&mut bytes, 4, 7);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 2);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, symbol_offset as u32);
    put32(&mut bytes, header + 12, 1);
    put32(&mut bytes, header + 16, string_offset as u32);
    put32(&mut bytes, header + 20, 4);
    put32(&mut bytes, symbol_offset, 9);
    bytes[symbol_offset + 4] = 0x0f;
    bytes[symbol_offset + 5] = 2;
    put16(&mut bytes, symbol_offset + 6, 0x40);
    put32(&mut bytes, symbol_offset + 8, 0x1234);
    bytes[string_offset] = 0;

    let image = macho::read(&bytes).expect("unresolved nlist is retained");
    assert_eq!(image.nlist_symbols.len(), 1);
    let symbol = &image.nlist_symbols[0];
    assert_eq!(symbol.string_index, 9);
    assert_eq!(symbol.n_type, 0x0f);
    assert_eq!(symbol.n_sect, 2);
    assert_eq!(symbol.n_desc, 0x40);
    assert_eq!(symbol.n_value, 0x1234);
    assert!(symbol.name.is_none());
    assert!(!symbol.valid);
    assert!(
        image
            .symbol_issues
            .iter()
            .any(|issue| issue.contains("outside the string table"))
    );
}

#[test]
fn decodes_bounded_linker_option_strings() {
    let header = 32;
    let command = 24;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x2d);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 2);
    bytes[header + 12..header + 20].copy_from_slice(b"foo\0bar\0");

    let image = macho::read(&bytes).expect("valid linker options");
    let options = &image.linker_options[0];
    assert_eq!(options.declared_count, 2);
    assert_eq!(options.options, vec!["foo", "bar"]);
    assert_eq!(options.raw_options, vec![b"foo".to_vec(), b"bar".to_vec()]);
    assert_eq!(options.option_records.len(), 2);
    assert_eq!(
        options.option_records[0].source_offset,
        (header + 12) as u64
    );
    assert_eq!(options.option_records[0].source_size, 4);
    assert!(options.option_records.iter().all(|record| record.valid));
    assert!(options.valid);
}

#[test]
fn records_truncated_linker_option_string() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x2d);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 1);
    bytes[header + 12..header + 16].copy_from_slice(b"opt!");

    let image = macho::read(&bytes).expect("truncated linker option remains observable");
    assert!(!image.linker_options[0].valid);
    assert!(
        image
            .path_issues
            .iter()
            .any(|issue| issue.contains("unterminated"))
    );
}

#[test]
fn retains_invalid_utf8_linker_option_bytes() {
    let header = 32;
    let command = 16;
    let mut bytes = vec![0u8; header + command];
    put32(&mut bytes, 0, 0xfeedfacf);
    put32(&mut bytes, 4, 0x0100000c);
    put32(&mut bytes, 12, 1);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, command as u32);
    put32(&mut bytes, header, 0x2d);
    put32(&mut bytes, header + 4, command as u32);
    put32(&mut bytes, header + 8, 1);
    bytes[header + 12..header + 16].copy_from_slice(&[0xff, b'x', 0, 0]);

    let image = macho::read(&bytes).expect("invalid UTF-8 remains observable");
    let option = &image.linker_options[0].option_records[0];
    assert_eq!(option.raw_bytes, vec![0xff, b'x']);
    assert!(!option.utf8_valid);
    assert!(!option.valid);
    assert!(!image.linker_options[0].valid);
    assert!(
        image
            .path_issues
            .iter()
            .any(|issue| issue.contains("not valid UTF-8"))
    );
}
