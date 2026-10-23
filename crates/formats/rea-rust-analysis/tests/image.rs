//! Independently laid-out native records exercise the public image reader.
use rea_rust_analysis::image::{self, ByteOrder, ContainerError, Error, Format};

// Independently encoded with Node 24.18.0 zlib: {"packages":[]}.
const ZLIB: &[u8] = &[
    120, 156, 171, 86, 42, 72, 76, 206, 78, 76, 79, 45, 86, 178, 138, 142, 173, 5, 0, 43, 187, 5,
    110,
];
const MARKER: &[u8] = b"/rustc/0123456789abcdef0123456789abcdef01234567/";

fn put16(bytes: &mut [u8], at: usize, value: u16, little: bool) {
    bytes[at..at + 2].copy_from_slice(&if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    });
}
fn put32(bytes: &mut [u8], at: usize, value: u32, little: bool) {
    bytes[at..at + 4].copy_from_slice(&if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    });
}
fn word(bytes: &mut [u8], at: usize, value: u64, bits: u8, little: bool) {
    if bits == 32 {
        put32(bytes, at, u32::try_from(value).unwrap(), little);
    } else {
        bytes[at..at + 8].copy_from_slice(&if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        });
    }
}
fn payload(bytes: &mut [u8]) {
    bytes[512..512 + ZLIB.len()].copy_from_slice(ZLIB);
    bytes[1024..1024 + MARKER.len()].copy_from_slice(MARKER);
}

fn elf(bits: u8, little: bool) -> Vec<u8> {
    let mut b = vec![0; 1536];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = if bits == 64 { 2 } else { 1 };
    b[5] = if little { 1 } else { 2 };
    b[6] = 1;
    put16(&mut b, 18, if bits == 64 { 62 } else { 3 }, little);
    put32(&mut b, 20, 1, little);
    let (header, width, shoff, ehsize, shwidth, shcount, shnames) = if bits == 64 {
        (64, 64, 40, 52, 58, 60, 62)
    } else {
        (52, 40, 32, 40, 46, 48, 50)
    };
    word(&mut b, shoff, header as u64, bits, little);
    put16(&mut b, ehsize, header as u16, little);
    put16(&mut b, shwidth, width as u16, little);
    put16(&mut b, shcount, 4, little);
    put16(&mut b, shnames, 1, little);
    let names = b"\0.shstrtab\0.dep-v0\0.rodata\0";
    b[384..384 + names.len()].copy_from_slice(names);
    for (index, name, kind, flags, offset, size) in [
        (1, 1, 3, 0, 384, names.len()),
        (2, 11, 1, 0, 512, ZLIB.len()),
        (3, 19, 1, 2, 1024, MARKER.len()),
    ] {
        let h = header + index * width;
        put32(&mut b, h, name, little);
        put32(&mut b, h + 4, kind, little);
        word(&mut b, h + 8, flags, bits, little);
        word(
            &mut b,
            h + if bits == 64 { 24 } else { 16 },
            offset,
            bits,
            little,
        );
        word(
            &mut b,
            h + if bits == 64 { 32 } else { 20 },
            size as u64,
            bits,
            little,
        );
    }
    payload(&mut b);
    b
}

fn pe(bits: u8) -> Vec<u8> {
    let mut b = vec![0; 1536];
    b[..2].copy_from_slice(b"MZ");
    put16(&mut b, 8, 4, true);
    put32(&mut b, 60, 128, true);
    b[128..132].copy_from_slice(b"PE\0\0");
    put16(&mut b, 132, if bits == 64 { 0x8664 } else { 0x14c }, true);
    put16(&mut b, 134, 2, true);
    let optional_size = if bits == 64 { 112 } else { 96 };
    put16(&mut b, 148, optional_size as u16, true);
    put16(&mut b, 152, if bits == 64 { 0x20b } else { 0x10b }, true);
    word(
        &mut b,
        152 + if bits == 64 { 24 } else { 28 },
        0x400000,
        bits,
        true,
    );
    for (index, name, offset, size) in [
        (0, &b".dep-v0"[..], 512, ZLIB.len()),
        (1, &b".rdata"[..], 1024, MARKER.len()),
    ] {
        let h = 152 + optional_size + index * 40;
        b[h..h + name.len()].copy_from_slice(name);
        put32(&mut b, h + 8, size as u32, true);
        put32(&mut b, h + 12, 0x1000 + index as u32 * 0x1000, true);
        put32(&mut b, h + 16, 64, true);
        put32(&mut b, h + 20, offset, true);
        put32(&mut b, h + 36, 0x40000040, true);
    }
    // Deliberately nonzero file padding must not enter the compressed section.
    b[512 + ZLIB.len()..576].fill(0xab);
    payload(&mut b);
    b
}

fn macho(bits: u8, little: bool) -> Vec<u8> {
    let mut b = vec![0; 1536];
    put32(
        &mut b,
        0,
        if bits == 64 { 0xfeedfacf } else { 0xfeedface },
        little,
    );
    put32(&mut b, 4, if bits == 64 { 0x0100000c } else { 12 }, little);
    let (header, segment, width) = if bits == 64 {
        (32, 72, 80)
    } else {
        (28, 56, 68)
    };
    put32(&mut b, 16, 1, little);
    put32(&mut b, 20, (segment + 2 * width) as u32, little);
    put32(&mut b, header, if bits == 64 { 0x19 } else { 1 }, little);
    put32(&mut b, header + 4, (segment + 2 * width) as u32, little);
    b[header + 8..header + 14].copy_from_slice(b"__DATA");
    word(&mut b, header + 24, 0x1000, bits, little);
    word(
        &mut b,
        header + if bits == 64 { 32 } else { 28 },
        4096,
        bits,
        little,
    );
    word(
        &mut b,
        header + if bits == 64 { 48 } else { 36 },
        1536,
        bits,
        little,
    );
    put32(&mut b, header + if bits == 64 { 60 } else { 44 }, 1, little);
    put32(&mut b, header + if bits == 64 { 64 } else { 48 }, 2, little);
    for (index, name, offset, size) in [
        (0, &b".dep-v0"[..], 512, ZLIB.len()),
        (1, &b".rodata"[..], 1024, MARKER.len()),
    ] {
        let h = header + segment + index * width;
        b[h..h + name.len()].copy_from_slice(name);
        b[h + 16..h + 22].copy_from_slice(b"__DATA");
        word(&mut b, h + 32, 0x1000 + offset, bits, little);
        word(
            &mut b,
            h + if bits == 64 { 40 } else { 36 },
            size as u64,
            bits,
            little,
        );
        put32(
            &mut b,
            h + if bits == 64 { 48 } else { 40 },
            offset as u32,
            little,
        );
    }
    payload(&mut b);
    b
}

#[test]
fn reads_all_three_containers_with_exact_offsets_and_native_byte_order() {
    for bits in [32, 64] {
        for little in [false, true] {
            for (bytes, format, architecture) in [
                (
                    elf(bits, little),
                    "elf",
                    if bits == 64 { "amd64" } else { "386" },
                ),
                (
                    macho(bits, little),
                    "macho",
                    if bits == 64 { "arm64" } else { "arm" },
                ),
            ] {
                let result = image::read(&bytes).unwrap();
                assert_eq!(serde_json::to_value(result.format).unwrap(), format);
                assert_eq!(result.architecture, architecture);
                assert_eq!(result.bits, bits);
                assert!(matches!(
                    (result.byte_order, little),
                    (ByteOrder::Little, true) | (ByteOrder::Big, false)
                ));
                let metadata = result.auditable_metadata.unwrap();
                assert_eq!(metadata.file_offset, 512);
                assert_eq!(metadata.section_bytes, ZLIB.len());
                assert!(metadata.packages.is_empty());
                let commit = result.rustc_commit.unwrap();
                assert_eq!(commit.evidence_kind, "inferred");
                assert_eq!(commit.hashes.len(), 1);
                assert_eq!(commit.hashes[0].file_offset, 1024);
                assert_eq!(
                    commit.hashes[0].hash,
                    "0123456789abcdef0123456789abcdef01234567"
                );
            }
        }
        let result = image::read(&pe(bits)).unwrap();
        assert!(matches!(result.format, Format::Pe));
        assert_eq!(result.bits, bits);
        assert_eq!(result.auditable_metadata.unwrap().section_bytes, ZLIB.len());
        assert_eq!(result.rustc_commit.unwrap().hashes[0].file_offset, 1024);
    }
}

#[test]
fn does_not_scan_writable_executable_or_unbacked_data() {
    for flags in [3, 6, 0x802] {
        let mut bytes = elf(64, true);
        word(&mut bytes, 64 + 3 * 64 + 8, flags, 64, true);
        assert!(image::read(&bytes).unwrap().rustc_commit.is_none());
    }
    let mut bytes = elf(64, true);
    word(&mut bytes, 64 + 3 * 64 + 24, u64::MAX, 64, true);
    assert!(image::read(&bytes).unwrap().rustc_commit.is_none());
    let mut bytes = macho(64, true);
    put32(&mut bytes, 32 + 60, 3, true);
    assert!(image::read(&bytes).unwrap().rustc_commit.is_none());
    let mut bytes = pe(64);
    put32(&mut bytes, 152 + 112 + 40 + 36, 0xe0000040, true);
    assert!(image::read(&bytes).unwrap().rustc_commit.is_none());
}

#[test]
fn preserves_scan_coverage_for_long_names_and_adjacent_overlapping_sections() {
    let mut bytes = elf(64, true);
    word(&mut bytes, 64 + 64 + 32, 128, 64, true);
    put32(&mut bytes, 64 + 3 * 64, 40, true);
    bytes[384 + 40..384 + 105].fill(b'x');
    assert_eq!(
        image::read(&bytes).unwrap().rustc_commit.unwrap().hashes[0].file_offset,
        1024
    );
    for second_start in [1024, 1044] {
        let mut bytes = elf(64, true);
        put32(&mut bytes, 64 + 2 * 64, 19, true);
        word(&mut bytes, 64 + 2 * 64 + 8, 2, 64, true);
        word(&mut bytes, 64 + 2 * 64 + 24, 1024, 64, true);
        word(&mut bytes, 64 + 2 * 64 + 32, 20, 64, true);
        word(&mut bytes, 64 + 3 * 64 + 24, second_start, 64, true);
        word(&mut bytes, 64 + 3 * 64 + 32, 1072 - second_start, 64, true);
        let result = image::read(&bytes).unwrap();
        assert!(result.auditable_metadata.is_none());
        assert_eq!(result.rustc_commit.unwrap().hashes[0].file_offset, 1024);
    }
}

#[test]
fn finds_overlapping_prefixes_and_deduplicates_hashes_before_allocating_output() {
    let mut bytes = elf(64, true);
    bytes[1024..1030].copy_from_slice(b"/rustc");
    bytes[1030..1030 + 48].copy_from_slice(MARKER);
    bytes[1078..1126].copy_from_slice(MARKER);
    word(&mut bytes, 64 + 3 * 64 + 32, 102, 64, true);
    let hashes = image::read(&bytes).unwrap().rustc_commit.unwrap().hashes;
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].file_offset, 1030);
}

#[test]
fn refuses_duplicate_compressed_and_non_file_backed_dependency_sections() {
    let mut bytes = elf(64, true);
    put32(&mut bytes, 64 + 3 * 64, 11, true);
    assert!(matches!(
        image::read(&bytes),
        Err(Error::Container(ContainerError::Malformed(_)))
    ));
    let mut bytes = elf(64, true);
    word(&mut bytes, 64 + 2 * 64 + 8, 0x800, 64, true);
    assert!(matches!(
        image::read(&bytes),
        Err(Error::Container(ContainerError::Unsupported(_)))
    ));
    let mut bytes = elf(64, true);
    put32(&mut bytes, 64 + 2 * 64 + 4, 8, true);
    assert!(matches!(
        image::read(&bytes),
        Err(Error::Container(ContainerError::Malformed(_)))
    ));
    let mut bytes = macho(64, true);
    word(&mut bytes, 32 + 72 + 32, 0x9000, 64, true);
    assert!(matches!(
        image::read(&bytes),
        Err(Error::Container(ContainerError::Malformed(_)))
    ));
}

#[test]
fn retains_unknown_machine_identity_and_refuses_structural_overflow() {
    let mut bytes = elf(64, true);
    put16(&mut bytes, 18, 0xf001, true);
    assert_eq!(
        image::read(&bytes).unwrap().architecture,
        "elf-machine-61441"
    );
    // Extended count is valid numerically but exceeds the actual table budget.
    put16(&mut bytes, 60, 0, true);
    word(&mut bytes, 64 + 32, 0x100000, 64, true);
    assert!(matches!(
        image::read(&bytes),
        Err(Error::Container(ContainerError::StructureLimit))
    ));
    let mut bytes = macho(64, true);
    word(&mut bytes, 32 + 24, u64::MAX, 64, true);
    assert!(matches!(
        image::read(&bytes),
        Err(Error::Container(ContainerError::Malformed(_)))
    ));
    let mut bytes = pe(64);
    put32(&mut bytes, 152 + 108, 1, true);
    assert!(matches!(
        image::read(&bytes),
        Err(Error::Container(ContainerError::Malformed(_)))
    ));
}

#[test]
fn truncated_headers_and_tables_return_errors_without_panicking() {
    for bytes in [
        elf(64, true),
        elf(32, false),
        macho(64, true),
        macho(32, false),
        pe(64),
        pe(32),
    ] {
        for size in 0..512 + ZLIB.len() {
            assert!(image::read(&bytes[..size]).is_err(), "prefix {size}");
        }
    }
    assert!(matches!(
        image::read(b"unrecognized"),
        Err(Error::Container(ContainerError::Unsupported(_)))
    ));
}

#[test]
fn compiler_hash_capacity_refuses_the_next_distinct_hash_not_repetitions() {
    for count in [64, 65] {
        let mut bytes = elf(64, true);
        bytes.resize(1024 + count * 48, 0);
        for index in 0..count {
            let marker = format!("/rustc/{index:040x}/");
            bytes[1024 + index * 48..1024 + (index + 1) * 48].copy_from_slice(marker.as_bytes());
        }
        word(&mut bytes, 64 + 3 * 64 + 32, (count * 48) as u64, 64, true);
        if count == 64 {
            assert_eq!(
                image::read(&bytes)
                    .unwrap()
                    .rustc_commit
                    .unwrap()
                    .hashes
                    .len(),
                64
            );
        } else {
            assert!(matches!(image::read(&bytes), Err(Error::CompilerHashLimit)));
            let first = bytes[1024..1072].to_vec();
            bytes[1024 + 64 * 48..1024 + 65 * 48].copy_from_slice(&first);
            assert_eq!(
                image::read(&bytes)
                    .unwrap()
                    .rustc_commit
                    .unwrap()
                    .hashes
                    .len(),
                64
            );
        }
    }
}

#[test]
fn distinguishes_unsupported_legacy_mz_images_from_corrupt_pe_headers() {
    let mut dos = vec![0; 64];
    dos[..2].copy_from_slice(b"MZ");
    put16(&mut dos, 2, 64, true);
    put16(&mut dos, 4, 1, true);
    put16(&mut dos, 8, 2, true);
    assert!(matches!(
        image::read(&dos),
        Err(Error::Container(ContainerError::Unsupported(_)))
    ));
    let mut legacy = vec![0; 128];
    legacy[..2].copy_from_slice(b"MZ");
    put16(&mut legacy, 8, 4, true);
    put32(&mut legacy, 60, 64, true);
    for signature in [b"NE", b"LE", b"LX"] {
        legacy[64..66].copy_from_slice(signature);
        assert!(matches!(
            image::read(&legacy),
            Err(Error::Container(ContainerError::Unsupported(_)))
        ));
    }
    legacy[64..66].copy_from_slice(b"XX");
    assert!(matches!(
        image::read(&legacy),
        Err(Error::Container(ContainerError::Malformed(_)))
    ));
}
