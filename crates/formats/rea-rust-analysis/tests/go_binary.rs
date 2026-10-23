use rea_rust_analysis::go::binary::{self as go_binary, Encoding, Error};
use serde_json::json;

const HEADER_OFFSET: usize = 1024;
const BASE: u64 = 0x10000;
const VERSION: &[u8] = b"go1.26.0";
const MODULE_TEXT: &[u8] = b"path\tapp\n";
const MODULE_START: &[u8] = &[
    0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6,
];
const MODULE_END: &[u8] = &[
    0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8, 0xf2,
];

#[derive(Clone, Copy)]
enum Format {
    Elf,
    Pe,
    MachO,
}

#[derive(Clone, Copy)]
enum StringEncoding {
    Inline,
    Pointer,
}

struct Fixture {
    bytes: Vec<u8>,
    version_offset: usize,
    module_offset: usize,
    module_bytes: Vec<u8>,
}

fn fixture(format: Format, bits: u8, little: bool, encoding: StringEncoding) -> Fixture {
    let mut bytes = vec![0; 4096];
    let mut module_bytes = MODULE_START.to_vec();
    module_bytes.extend_from_slice(MODULE_TEXT);
    module_bytes.extend_from_slice(MODULE_END);

    write_container(&mut bytes, format, bits, little);
    bytes[HEADER_OFFSET..HEADER_OFFSET + 14].copy_from_slice(b"\xff Go buildinf:");
    bytes[HEADER_OFFSET + 14] = bits / 8;
    bytes[HEADER_OFFSET + 15] = u8::from(!little)
        | match encoding {
            StringEncoding::Inline => 2,
            StringEncoding::Pointer => 0,
        };

    let (version_offset, module_offset) = match encoding {
        StringEncoding::Inline => {
            let version_length = encode_varint(VERSION.len());
            let version_offset = HEADER_OFFSET + 32 + version_length.len();
            let module_length = encode_varint(module_bytes.len());
            let module_length_offset = version_offset + VERSION.len();
            let module_offset = module_length_offset + module_length.len();
            copy_at(&mut bytes, HEADER_OFFSET + 32, &version_length);
            copy_at(&mut bytes, version_offset, VERSION);
            copy_at(&mut bytes, module_length_offset, &module_length);
            copy_at(&mut bytes, module_offset, &module_bytes);
            (version_offset, module_offset)
        }
        StringEncoding::Pointer => {
            let width = usize::from(bits / 8);
            let version_header = 1536;
            let module_header = version_header + width * 2;
            let version_offset = 2048;
            let module_offset = 2304;
            write_word(
                &mut bytes,
                HEADER_OFFSET + 16,
                BASE + version_header as u64,
                bits,
                little,
            );
            write_word(
                &mut bytes,
                HEADER_OFFSET + 16 + width,
                BASE + module_header as u64,
                bits,
                little,
            );
            write_word(
                &mut bytes,
                version_header,
                BASE + version_offset as u64,
                bits,
                little,
            );
            write_word(
                &mut bytes,
                version_header + width,
                VERSION.len() as u64,
                bits,
                little,
            );
            write_word(
                &mut bytes,
                module_header,
                BASE + module_offset as u64,
                bits,
                little,
            );
            write_word(
                &mut bytes,
                module_header + width,
                module_bytes.len() as u64,
                bits,
                little,
            );
            copy_at(&mut bytes, version_offset, VERSION);
            copy_at(&mut bytes, module_offset, &module_bytes);
            (version_offset, module_offset)
        }
    };

    Fixture {
        bytes,
        version_offset,
        module_offset,
        module_bytes,
    }
}

fn write_container(bytes: &mut [u8], format: Format, bits: u8, little: bool) {
    match format {
        Format::Elf => write_elf(bytes, bits, little),
        Format::Pe => write_pe(bytes, bits),
        Format::MachO => write_macho(bytes, bits, little),
    }
}

fn write_elf(bytes: &mut [u8], bits: u8, little: bool) {
    let wide = bits == 64;
    bytes[..7].copy_from_slice(&[
        0x7f,
        b'E',
        b'L',
        b'F',
        if wide { 2 } else { 1 },
        if little { 1 } else { 2 },
        1,
    ]);
    write_u16(bytes, 16, 2, little);
    write_u16(bytes, 18, if wide { 62 } else { 3 }, little);
    write_u32(bytes, 20, 1, little);
    write_word(bytes, if wide { 32 } else { 28 }, 128, bits, little);
    write_word(bytes, if wide { 40 } else { 32 }, 256, bits, little);
    write_u16(
        bytes,
        if wide { 52 } else { 40 },
        if wide { 64 } else { 52 },
        little,
    );
    write_u16(
        bytes,
        if wide { 54 } else { 42 },
        if wide { 56 } else { 32 },
        little,
    );
    write_u16(bytes, if wide { 56 } else { 44 }, 1, little);
    write_u16(
        bytes,
        if wide { 58 } else { 46 },
        if wide { 64 } else { 40 },
        little,
    );
    write_u16(bytes, if wide { 60 } else { 48 }, 3, little);
    write_u16(bytes, if wide { 62 } else { 50 }, 1, little);

    write_u32(bytes, 128, 1, little);
    if wide {
        write_u32(bytes, 132, 6, little);
        write_word(bytes, 136, 0, bits, little);
        write_word(bytes, 144, BASE, bits, little);
        write_word(bytes, 160, bytes.len() as u64, bits, little);
        write_word(bytes, 168, bytes.len() as u64, bits, little);
    } else {
        write_word(bytes, 132, 0, bits, little);
        write_word(bytes, 136, BASE, bits, little);
        write_word(bytes, 144, bytes.len() as u64, bits, little);
        write_word(bytes, 148, bytes.len() as u64, bits, little);
        write_u32(bytes, 152, 6, little);
    }

    let entry_size = if wide { 64 } else { 40 };
    copy_at(bytes, 768, b"\0.shstrtab\0.go.buildinfo\0");
    let names = 256 + entry_size;
    write_u32(bytes, names, 1, little);
    write_u32(bytes, names + 4, 3, little);
    write_word(bytes, names + if wide { 24 } else { 16 }, 768, bits, little);
    write_word(
        bytes,
        names + if wide { 32 } else { 20 },
        b"\0.shstrtab\0.go.buildinfo\0".len() as u64,
        bits,
        little,
    );
    let info = 256 + entry_size * 2;
    write_u32(bytes, info, 11, little);
    write_u32(bytes, info + 4, 1, little);
    write_word(
        bytes,
        info + if wide { 16 } else { 12 },
        BASE + HEADER_OFFSET as u64,
        bits,
        little,
    );
    write_word(
        bytes,
        info + if wide { 24 } else { 16 },
        HEADER_OFFSET as u64,
        bits,
        little,
    );
    write_word(bytes, info + if wide { 32 } else { 20 }, 2048, bits, little);
}

fn write_pe(bytes: &mut [u8], bits: u8) {
    bytes[..2].copy_from_slice(b"MZ");
    write_u32(bytes, 60, 128, true);
    copy_at(bytes, 128, b"PE\0\0");
    write_u16(bytes, 132, if bits == 64 { 0x8664 } else { 0x14c }, true);
    write_u16(bytes, 134, 1, true);
    let optional_size = if bits == 64 { 112 } else { 96 };
    write_u16(bytes, 148, optional_size, true);
    write_u16(bytes, 152, if bits == 64 { 0x20b } else { 0x10b }, true);
    write_word(
        bytes,
        152 + if bits == 64 { 24 } else { 28 },
        BASE,
        bits,
        true,
    );
    let section = 152 + optional_size as usize;
    copy_at(bytes, section, b".data");
    write_u32(bytes, section + 8, 2048, true);
    write_u32(bytes, section + 12, HEADER_OFFSET as u32, true);
    write_u32(bytes, section + 16, 2048, true);
    write_u32(bytes, section + 20, HEADER_OFFSET as u32, true);
    write_u32(bytes, section + 36, 0xc0000040, true);
}

fn write_macho(bytes: &mut [u8], bits: u8, little: bool) {
    let wide = bits == 64;
    write_u32(bytes, 0, if wide { 0xfeedfacf } else { 0xfeedface }, little);
    write_u32(bytes, 4, if wide { 0x01000007 } else { 7 }, little);
    write_u32(bytes, 8, 3, little);
    write_u32(bytes, 12, 2, little);
    write_u32(bytes, 16, 1, little);
    let segment_size = if wide { 72 } else { 56 };
    let section_size = if wide { 80 } else { 68 };
    write_u32(bytes, 20, (segment_size + section_size) as u32, little);
    let command = if wide { 32 } else { 28 };
    write_u32(bytes, command, if wide { 0x19 } else { 1 }, little);
    write_u32(
        bytes,
        command + 4,
        (segment_size + section_size) as u32,
        little,
    );
    copy_at(bytes, command + 8, b"__DATA");
    write_word(bytes, command + 24, BASE, bits, little);
    write_word(
        bytes,
        command + if wide { 32 } else { 28 },
        bytes.len() as u64,
        bits,
        little,
    );
    write_word(bytes, command + if wide { 40 } else { 32 }, 0, bits, little);
    write_word(
        bytes,
        command + if wide { 48 } else { 36 },
        bytes.len() as u64,
        bits,
        little,
    );
    write_u32(bytes, command + if wide { 56 } else { 40 }, 3, little);
    write_u32(bytes, command + if wide { 60 } else { 44 }, 3, little);
    write_u32(bytes, command + if wide { 64 } else { 48 }, 1, little);
    let section = command + segment_size;
    copy_at(bytes, section, b"__go_buildinfo");
    copy_at(bytes, section + 16, b"__DATA");
    write_word(
        bytes,
        section + 32,
        BASE + HEADER_OFFSET as u64,
        bits,
        little,
    );
    write_word(
        bytes,
        section + if wide { 40 } else { 36 },
        2048,
        bits,
        little,
    );
    write_u32(
        bytes,
        section + if wide { 48 } else { 40 },
        HEADER_OFFSET as u32,
        little,
    );
}

fn encode_varint(mut value: usize) -> Vec<u8> {
    let mut output = Vec::new();
    while value >= 128 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
    output
}

fn copy_at(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes[offset..offset + value.len()].copy_from_slice(value);
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16, little: bool) {
    let encoded = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    copy_at(bytes, offset, &encoded);
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32, little: bool) {
    let encoded = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    copy_at(bytes, offset, &encoded);
}

fn write_word(bytes: &mut [u8], offset: usize, value: u64, bits: u8, little: bool) {
    if bits == 32 {
        write_u32(bytes, offset, value as u32, little);
    } else {
        let encoded = if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        copy_at(bytes, offset, &encoded);
    }
}

#[test]
fn decodes_inline_go_metadata_from_elf_pe_and_thin_macho() {
    let cases = [
        (Format::Elf, 32, true),
        (Format::Elf, 32, false),
        (Format::Elf, 64, true),
        (Format::Elf, 64, false),
        (Format::Pe, 32, true),
        (Format::Pe, 64, true),
        (Format::MachO, 32, true),
        (Format::MachO, 32, false),
        (Format::MachO, 64, true),
        (Format::MachO, 64, false),
    ];

    for (format, bits, little) in cases {
        let fixture = fixture(format, bits, little, StringEncoding::Inline);
        let image = go_binary::read(&fixture.bytes).unwrap();
        let value = serde_json::to_value(image).unwrap();
        assert_eq!(value["bits"], bits);
        assert_eq!(value["byte_order"], if little { "little" } else { "big" });
        assert_eq!(value["build_info"]["header_offset"], HEADER_OFFSET);
        assert_eq!(value["build_info"]["encoding"], "inline");
        assert_eq!(value["build_info"]["go_version"], "go1.26.0");
        assert_eq!(
            value["build_info"]["version_location"]["offset"],
            fixture.version_offset
        );
        assert_eq!(
            value["build_info"]["module_location"]["offset"],
            fixture.module_offset
        );
        assert_eq!(
            value["build_info"]["module_bytes_base64"],
            "MHevDJJ0CAJB4cEH5tYY5nBhdGgJYXBwCvkyQzGGGCByAIJCEEEW2PI="
        );
    }
}

#[test]
fn follows_historical_pointer_strings_in_elf_pe_and_thin_macho() {
    for format in [Format::Elf, Format::Pe, Format::MachO] {
        let fixture = fixture(format, 64, true, StringEncoding::Pointer);
        let image = go_binary::read(&fixture.bytes).unwrap();
        let info = image.build_info.unwrap();
        assert!(matches!(info.encoding, Encoding::Pointer));
        assert_eq!(info.go_version.as_deref(), Some("go1.26.0"));
        assert_eq!(info.version_location.offset, fixture.version_offset);
        assert_eq!(info.module_location.offset, fixture.module_offset);
        assert_eq!(info.module_text.as_deref(), Some("path\tapp\n"));
    }
}

#[test]
fn preserves_undecodable_go_string_bytes_and_rejects_bad_framing() {
    let mut fixture = fixture(Format::Elf, 64, true, StringEncoding::Inline);
    fixture.bytes[fixture.version_offset] = 0xff;
    let image = go_binary::read(&fixture.bytes).unwrap();
    let value = serde_json::to_value(image).unwrap();
    assert_eq!(value["build_info"]["go_version"], Value::Null);
    assert_eq!(
        value["build_info"]["go_version_bytes_base64"],
        "/28xLjI2LjA="
    );

    fixture.bytes[fixture.module_offset] = 0;
    assert!(matches!(
        go_binary::read(&fixture.bytes),
        Err(Error::Malformed("Go module string framing is invalid"))
    ));
}

#[test]
fn retains_absence_and_rejects_unsupported_or_truncated_metadata() {
    let mut absent = fixture(Format::Elf, 64, true, StringEncoding::Inline);
    absent.bytes[HEADER_OFFSET..HEADER_OFFSET + 14].fill(0);
    assert!(go_binary::read(&absent.bytes).unwrap().build_info.is_none());

    let mut unsupported = fixture(Format::Elf, 64, true, StringEncoding::Inline);
    unsupported.bytes[HEADER_OFFSET + 15] = 0x80;
    assert!(matches!(
        go_binary::read(&unsupported.bytes),
        Err(Error::Unsupported(_))
    ));

    let mut truncated = fixture(Format::Elf, 64, true, StringEncoding::Inline);
    truncated.bytes[HEADER_OFFSET + 32] = 0x80;
    assert!(matches!(
        go_binary::read(&truncated.bytes),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn serializes_the_native_go_image_contract_shape() {
    let fixture = fixture(Format::Elf, 64, true, StringEncoding::Inline);
    let value = serde_json::to_value(go_binary::read(&fixture.bytes).unwrap()).unwrap();
    assert_eq!(value["format"], "elf");
    assert_eq!(value["architecture"], "amd64");
    assert_eq!(value["bits"], 64);
    assert_eq!(
        value["build_info"]["version_location"],
        json!({"offset": fixture.version_offset, "bytes": VERSION.len()})
    );
    assert_eq!(
        value["build_info"]["module_location"],
        json!({"offset": fixture.module_offset, "bytes": fixture.module_bytes.len()})
    );
}

use serde_json::Value;
