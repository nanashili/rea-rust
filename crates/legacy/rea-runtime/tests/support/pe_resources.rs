use std::collections::BTreeMap;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
enum Identity {
    Name(String),
    Id(u16),
}

enum Node {
    Directory(BTreeMap<Identity, Node>),
    Resource(Vec<u8>),
}

pub fn fixture(plus: bool) -> Vec<u8> {
    let mut root = Node::Directory(BTreeMap::new());
    insert_resource(&mut root, &[3, 1, 1033], b"ICON");
    insert_resource(&mut root, &[3, 1, 1041], b"JAPN");
    insert_named_resource(&mut root, 10, "7", 1033, b"Hello");
    insert_resource(&mut root, &[10, 7, 1041], b"World");
    insert_resource(&mut root, &[14, 42, 1033], &icon_group());

    build_fixture(plus, &root).bytes
}

#[derive(Clone, Copy, Debug)]
pub struct ResourceOffsets {
    pub payload: usize,
}

/// Build one resource at the requested identities and return its file offsets.
///
/// Type-specific projection tests use this fixture so their payload can grow
/// without overlapping neighboring resource data and their directory identity
/// matches the resource type under test.
pub fn fixture_with_resource(
    plus: bool,
    resource_type: u16,
    name: u16,
    language: u16,
    payload: &[u8],
) -> (Vec<u8>, ResourceOffsets) {
    let mut root = Node::Directory(BTreeMap::new());
    insert_resource(&mut root, &[resource_type, name, language], payload);

    let fixture = build_fixture(plus, &root);
    let resource = fixture
        .resources
        .first()
        .copied()
        .expect("single-resource fixture contains its data entry");

    (fixture.bytes, resource)
}

struct BuiltFixture {
    bytes: Vec<u8>,
    resources: Vec<ResourceOffsets>,
}

fn build_fixture(plus: bool, root: &Node) -> BuiltFixture {
    let mut section = Vec::new();
    let mut data_entries = Vec::new();
    emit_directory(root, &mut section, &mut data_entries);
    let mut resources = Vec::with_capacity(data_entries.len());

    for (data_entry, payload) in data_entries {
        let payload_offset = allocate(&mut section, payload.len(), 64);
        section[payload_offset..payload_offset + payload.len()].copy_from_slice(&payload);
        write_u32(&mut section, data_entry, 0x2000 + payload_offset as u32);
        write_u32(&mut section, data_entry + 4, payload.len() as u32);
        write_u32(&mut section, data_entry + 8, 65001);

        resources.push(ResourceOffsets {
            payload: 0x400 + payload_offset,
        });
    }

    BuiltFixture {
        bytes: build_pe(plus, &section),
        resources,
    }
}

fn insert_resource(root: &mut Node, path: &[u16], payload: &[u8]) {
    let identities = path.iter().copied().map(Identity::Id).collect::<Vec<_>>();
    insert(root, &identities, payload);
}

fn insert_named_resource(
    root: &mut Node,
    resource_type: u16,
    name: &str,
    language: u16,
    payload: &[u8],
) {
    let identities = vec![
        Identity::Id(resource_type),
        Identity::Name(name.into()),
        Identity::Id(language),
    ];
    insert(root, &identities, payload);
}

fn insert(root: &mut Node, path: &[Identity], payload: &[u8]) {
    let Some((identity, tail)) = path.split_first() else {
        return;
    };
    let Node::Directory(children) = root else {
        return;
    };

    if tail.is_empty() {
        children.insert(identity.clone(), Node::Resource(payload.to_vec()));
        return;
    }

    let child = children
        .entry(identity.clone())
        .or_insert_with(|| Node::Directory(BTreeMap::new()));
    insert(child, tail, payload);
}

fn emit_directory(
    node: &Node,
    section: &mut Vec<u8>,
    data_entries: &mut Vec<(usize, Vec<u8>)>,
) -> usize {
    let Node::Directory(children) = node else {
        return 0;
    };

    let directory_offset = allocate(section, 16 + children.len() * 8, 4);
    let named_count = children
        .keys()
        .filter(|identity| matches!(identity, Identity::Name(_)))
        .count();
    write_u16(section, directory_offset + 12, named_count as u16);
    write_u16(
        section,
        directory_offset + 14,
        (children.len() - named_count) as u16,
    );

    for (index, (identity, child)) in children.iter().enumerate() {
        let entry_offset = directory_offset + 16 + index * 8;
        match identity {
            Identity::Name(name) => {
                let name_offset = allocate(section, 2 + name.encode_utf16().count() * 2, 2);
                let units = name.encode_utf16().collect::<Vec<_>>();
                write_u16(section, name_offset, units.len() as u16);
                for (unit_index, unit) in units.into_iter().enumerate() {
                    write_u16(section, name_offset + 2 + unit_index * 2, unit);
                }
                write_u32(section, entry_offset, 0x8000_0000 | name_offset as u32);
            }
            Identity::Id(id) => write_u32(section, entry_offset, u32::from(*id)),
        }

        match child {
            Node::Directory(_) => {
                let child_offset = emit_directory(child, section, data_entries);
                write_u32(section, entry_offset + 4, 0x8000_0000 | child_offset as u32);
            }
            Node::Resource(payload) => {
                let data_offset = allocate(section, 16, 4);
                write_u32(section, entry_offset + 4, data_offset as u32);
                data_entries.push((data_offset, payload.clone()));
            }
        }
    }

    directory_offset
}

fn icon_group() -> Vec<u8> {
    let mut bytes = vec![0; 34];
    write_u16(&mut bytes, 2, 1);
    write_u16(&mut bytes, 4, 2);

    for (index, resource_id) in [1_u16, 99].into_iter().enumerate() {
        let entry = 6 + index * 14;
        bytes[entry] = 16;
        bytes[entry + 1] = 16;
        write_u16(&mut bytes, entry + 4, 1);
        write_u16(&mut bytes, entry + 6, 32);
        write_u32(&mut bytes, entry + 8, 4);
        write_u16(&mut bytes, entry + 12, resource_id);
    }

    bytes
}

fn build_pe(plus: bool, section: &[u8]) -> Vec<u8> {
    let optional_size = if plus { 240 } else { 224 };
    let section_header = 0x98 + optional_size;
    let raw_size = align(section.len(), 512);
    let mut bytes = vec![0; 0x400 + raw_size];

    write_u16(&mut bytes, 0, 0x5a4d);
    write_u32(&mut bytes, 60, 0x80);
    write_u32(&mut bytes, 0x80, 0x0000_4550);
    write_u16(&mut bytes, 0x84, if plus { 0x8664 } else { 0x014c });
    write_u16(&mut bytes, 0x86, 1);
    write_u16(&mut bytes, 0x94, optional_size as u16);
    write_u16(&mut bytes, 0x98, if plus { 0x020b } else { 0x010b });

    let size_of_headers = 0x98 + optional_size + 40;
    write_u32(&mut bytes, 0x98 + 60, size_of_headers as u32);
    write_u32(&mut bytes, 0x98 + if plus { 108 } else { 92 }, 16);

    let data_directories = 0x98 + if plus { 112 } else { 96 };
    write_u32(&mut bytes, data_directories + 16, 0x2000);
    write_u32(&mut bytes, data_directories + 20, section.len() as u32);

    bytes[section_header..section_header + 5].copy_from_slice(b".rsrc");
    write_u32(&mut bytes, section_header + 8, section.len() as u32);
    write_u32(&mut bytes, section_header + 12, 0x2000);
    write_u32(&mut bytes, section_header + 16, raw_size as u32);
    write_u32(&mut bytes, section_header + 20, 0x400);
    bytes[0x400..0x400 + section.len()].copy_from_slice(section);

    bytes
}

fn allocate(section: &mut Vec<u8>, bytes: usize, alignment: usize) -> usize {
    let start = align(section.len(), alignment);
    section.resize(start + bytes, 0);
    start
}

fn align(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
