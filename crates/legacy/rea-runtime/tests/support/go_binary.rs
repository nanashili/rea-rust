const HEADER_OFFSET: usize = 1024;
const IMAGE_BASE: u64 = 0x10000;
const GO_VERSION: &[u8] = b"go1.26.0";
const MODULE_TEXT: &[&[u8]] = &[
    b"path\tgithub.com/acme/app\n",
    b"mod\tgithub.com/acme/app\tv1.2.3\th1:main\n",
    b"dep\tgithub.com/acme/lib\tv2.3.4\th1:library\n",
    b"build\tGOOS=linux\n",
];
const MODULE_START: &[u8] = &[
    0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6,
];
const MODULE_END: &[u8] = &[
    0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8, 0xf2,
];

pub fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    write_elf64(&mut bytes);
    write_section_table(&mut bytes);
    write_build_info(&mut bytes);
    bytes
}

fn write_elf64(bytes: &mut [u8]) {
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    write_u16(bytes, 16, 2);
    write_u16(bytes, 18, 62);
    write_u32(bytes, 20, 1);
    write_u64(bytes, 32, 128);
    write_u64(bytes, 40, 256);
    write_u16(bytes, 52, 64);
    write_u16(bytes, 54, 56);
    write_u16(bytes, 56, 1);
    write_u16(bytes, 58, 64);
    write_u16(bytes, 60, 3);
    write_u16(bytes, 62, 1);

    write_u32(bytes, 128, 1);
    write_u32(bytes, 132, 6);
    write_u64(bytes, 136, 0);
    write_u64(bytes, 144, IMAGE_BASE);
    write_u64(bytes, 160, bytes.len() as u64);
    write_u64(bytes, 168, bytes.len() as u64);
}

fn write_section_table(bytes: &mut [u8]) {
    const SECTION_NAMES_OFFSET: usize = 768;
    const SECTION_NAMES: &[u8] = b"\0.shstrtab\0.go.buildinfo\0";

    copy_at(bytes, SECTION_NAMES_OFFSET, SECTION_NAMES);

    let section_names = 256 + 64;
    write_u32(bytes, section_names, 1);
    write_u32(bytes, section_names + 4, 3);
    write_u64(bytes, section_names + 24, SECTION_NAMES_OFFSET as u64);
    write_u64(bytes, section_names + 32, SECTION_NAMES.len() as u64);

    let build_info = 256 + 128;
    write_u32(bytes, build_info, 11);
    write_u32(bytes, build_info + 4, 1);
    write_u64(bytes, build_info + 16, IMAGE_BASE + HEADER_OFFSET as u64);
    write_u64(bytes, build_info + 24, HEADER_OFFSET as u64);
    write_u64(bytes, build_info + 32, 2048);
}

fn write_build_info(bytes: &mut [u8]) {
    let mut module = MODULE_START.to_vec();
    for line in MODULE_TEXT {
        module.extend_from_slice(line);
    }
    module.extend_from_slice(MODULE_END);

    copy_at(bytes, HEADER_OFFSET, b"\xff Go buildinf:");
    bytes[HEADER_OFFSET + 14] = 8;
    bytes[HEADER_OFFSET + 15] = 2;

    let version_length = encode_varint(GO_VERSION.len());
    let version_offset = HEADER_OFFSET + 32 + version_length.len();
    let module_length_offset = version_offset + GO_VERSION.len();
    let module_length = encode_varint(module.len());
    let module_offset = module_length_offset + module_length.len();

    copy_at(bytes, HEADER_OFFSET + 32, &version_length);
    copy_at(bytes, version_offset, GO_VERSION);
    copy_at(bytes, module_length_offset, &module_length);
    copy_at(bytes, module_offset, &module);
}

fn encode_varint(mut value: usize) -> Vec<u8> {
    let mut encoded = Vec::new();
    while value >= 128 {
        encoded.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    encoded.push(value as u8);
    encoded
}

fn copy_at(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes[offset..offset + value.len()].copy_from_slice(value);
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    copy_at(bytes, offset, &value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    copy_at(bytes, offset, &value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    copy_at(bytes, offset, &value.to_le_bytes());
}
