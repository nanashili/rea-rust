//! ECMA-335 stream and table layout with checked byte extents.
//!
//! Port of `src/dotnet/ManagedMetadataLayout.ts`. The completed layout owns the
//! shared [`ManagedDecodeBudget`] for its lifetime (TS `attachManagedDecodeBudget`
//! plus the `managedDecodeBudget(layout)` WeakMap accessor).

use std::cell::RefCell;
use std::collections::BTreeMap;

use super::budget::ManagedDecodeBudget;
use super::bytes::{read_u16, read_u32, read_u64};
use super::failure::{InternalFailure, ManagedReaderFailure, managed_failure};
use super::row_sizes::{RowSizeContext, compute_row_size};

/// The ECMA-335 metadata table names, indexed by table number.
pub const METADATA_TABLE_NAMES: [&str; 45] = [
    "Module",
    "TypeRef",
    "TypeDef",
    "FieldPtr",
    "Field",
    "MethodPtr",
    "MethodDef",
    "ParamPtr",
    "Param",
    "InterfaceImpl",
    "MemberRef",
    "Constant",
    "CustomAttribute",
    "FieldMarshal",
    "DeclSecurity",
    "ClassLayout",
    "FieldLayout",
    "StandAloneSig",
    "EventMap",
    "EventPtr",
    "Event",
    "PropertyMap",
    "PropertyPtr",
    "Property",
    "MethodSemantics",
    "MethodImpl",
    "ModuleRef",
    "TypeSpec",
    "ImplMap",
    "FieldRVA",
    "ENCLog",
    "ENCMap",
    "Assembly",
    "AssemblyProcessor",
    "AssemblyOS",
    "AssemblyRef",
    "AssemblyRefProcessor",
    "AssemblyRefOS",
    "File",
    "ExportedType",
    "ManifestResource",
    "NestedClass",
    "GenericParam",
    "MethodSpec",
    "GenericParamConstraint",
];

/// Name of a table index, or `TableN` for an out-of-range index.
pub fn table_name(index: usize) -> String {
    METADATA_TABLE_NAMES
        .get(index)
        .map(|name| (*name).to_string())
        .unwrap_or_else(|| format!("Table{index}"))
}

/// A metadata stream within the root.
#[derive(Clone)]
pub struct MetadataStream {
    pub offset: i64,
    pub size: i64,
}

/// A validated metadata table layout.
#[derive(Clone)]
pub struct MetadataTableLayout {
    pub index: usize,
    pub name: String,
    pub row_count: i64,
    pub row_size: i64,
    pub offset: i64,
}

/// Coded index descriptors: bit width and candidate tables.
struct CodedIndex {
    bits: u32,
    tables: &'static [usize],
}

fn coded_index(name: &str) -> &'static CodedIndex {
    match name {
        "TypeDefOrRef" => &CodedIndex {
            bits: 2,
            tables: &[2, 1, 27],
        },
        "HasConstant" => &CodedIndex {
            bits: 2,
            tables: &[4, 8, 23],
        },
        "HasCustomAttribute" => &CodedIndex {
            bits: 5,
            tables: &[
                6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43,
            ],
        },
        "HasFieldMarshal" => &CodedIndex {
            bits: 1,
            tables: &[4, 8],
        },
        "HasDeclSecurity" => &CodedIndex {
            bits: 2,
            tables: &[2, 6, 32],
        },
        "MemberRefParent" => &CodedIndex {
            bits: 3,
            tables: &[2, 1, 26, 6, 27],
        },
        "HasSemantics" => &CodedIndex {
            bits: 1,
            tables: &[20, 23],
        },
        "MethodDefOrRef" => &CodedIndex {
            bits: 1,
            tables: &[6, 10],
        },
        "MemberForwarded" => &CodedIndex {
            bits: 1,
            tables: &[4, 6],
        },
        "Implementation" => &CodedIndex {
            bits: 2,
            tables: &[38, 35, 39],
        },
        "CustomAttributeType" => &CodedIndex {
            bits: 3,
            tables: &[6, 10],
        },
        "ResolutionScope" => &CodedIndex {
            bits: 2,
            tables: &[0, 26, 35, 1],
        },
        "TypeOrMethodDef" => &CodedIndex {
            bits: 1,
            tables: &[2, 6],
        },
        _ => unreachable!("unknown coded index {name}"),
    }
}

/// The parsed metadata layout, owner of the shared decode budget.
pub struct ManagedMetadataLayout {
    pub version: String,
    pub stream_names: Vec<String>,
    pub strings: MetadataStream,
    pub guid: MetadataStream,
    pub blob: MetadataStream,
    pub user_strings: Option<MetadataStream>,
    pub tables: BTreeMap<usize, MetadataTableLayout>,
    pub row_counts: Vec<i64>,
    pub string_index_size: i64,
    pub guid_index_size: i64,
    pub blob_index_size: i64,
    budget: RefCell<ManagedDecodeBudget>,
}

impl ManagedMetadataLayout {
    /// `table(index)`.
    pub fn table(&self, index: usize) -> Option<&MetadataTableLayout> {
        self.tables.get(&index)
    }

    /// `tableIndexSize(index)`: 2 or 4 bytes.
    pub fn table_index_size(&self, index: usize) -> i64 {
        table_size(index, &self.row_counts)
    }

    /// `codedIndexSize(name)`: 2 or 4 bytes.
    pub fn coded_index_size(&self, name: &str) -> i64 {
        coded_size(name, &self.row_counts)
    }

    /// The shared decode budget (`managedDecodeBudget(layout)`).
    pub fn budget(&self) -> std::cell::RefMut<'_, ManagedDecodeBudget> {
        self.budget.borrow_mut()
    }
}

fn require_range(
    bytes: &[u8],
    base: i64,
    offset: i64,
    length: i64,
    scope: &str,
) -> Result<(), ManagedReaderFailure> {
    let buffer_len = bytes.len() as i64;
    if offset < 0 || length < 0 || offset > buffer_len - length {
        return Err(managed_failure(
            "invalid-metadata-root",
            scope,
            format!("{scope} leaves the metadata byte range"),
            if offset >= 0 {
                Some((base + offset) as u64)
            } else {
                None
            },
        ));
    }
    Ok(())
}

fn align4(value: i64) -> i64 {
    value
        .div_euclid(4)
        .wrapping_add(if value.rem_euclid(4) == 0 { 0 } else { 1 })
        * 4
}

fn coded_size(name: &str, row_counts: &[i64]) -> i64 {
    let descriptor = coded_index(name);
    let mut maximum = 0i64;
    for &table in descriptor.tables {
        maximum = maximum.max(row_counts.get(table).copied().unwrap_or(0));
    }
    if maximum < (1i64 << (16 - descriptor.bits)) {
        2
    } else {
        4
    }
}

fn table_size(index: usize, rows: &[i64]) -> i64 {
    if rows.get(index).copied().unwrap_or(0) < 0x1_0000 {
        2
    } else {
        4
    }
}

fn read_u16_at(bytes: &[u8], offset: i64) -> Result<u16, ManagedReaderFailure> {
    read_u16(bytes, offset as usize).map_err(root_internal)
}

fn read_u32_at(bytes: &[u8], offset: i64) -> Result<u32, ManagedReaderFailure> {
    read_u32(bytes, offset as usize).map_err(root_internal)
}

fn root_internal(_internal: InternalFailure) -> ManagedReaderFailure {
    managed_failure(
        "invalid-metadata-root",
        "metadata.root",
        "Metadata read left the metadata byte range",
        None,
    )
}

/// `readStreamName`: read a bounded, printable-ASCII stream name.
fn read_stream_name(
    bytes: &[u8],
    root_offset: i64,
    offset: i64,
) -> Result<(String, i64), ManagedReaderFailure> {
    let end_limit = (bytes.len() as i64).min(offset + 32);
    let mut end = offset;
    while end < end_limit && bytes.get(end as usize).copied() != Some(0) {
        end += 1;
    }
    if end == end_limit {
        return Err(managed_failure(
            "invalid-stream",
            "metadata.stream-name",
            "Metadata stream name is missing a bounded terminator",
            Some((root_offset + offset) as u64),
        ));
    }
    let name_bytes = &bytes[offset as usize..end as usize];
    if name_bytes.iter().any(|&byte| byte < 0x20 || byte > 0x7e) {
        return Err(managed_failure(
            "invalid-stream",
            "metadata.stream-name",
            "Metadata stream name is not printable ASCII",
            Some((root_offset + offset) as u64),
        ));
    }
    let name = String::from_utf8_lossy(name_bytes).into_owned();
    Ok((name, align4(end + 1)))
}

fn stream_by_name<'a>(
    streams: &'a BTreeMap<String, MetadataStream>,
    names: &[&str],
) -> Option<&'a MetadataStream> {
    for name in names {
        if let Some(stream) = streams.get(*name) {
            return Some(stream);
        }
    }
    None
}

fn require_stream(
    streams: &BTreeMap<String, MetadataStream>,
    name: &str,
) -> Result<MetadataStream, ManagedReaderFailure> {
    streams.get(name).cloned().ok_or_else(|| {
        managed_failure(
            "missing-stream",
            format!("metadata.{name}"),
            format!("Required metadata stream {name} is absent"),
            None,
        )
    })
}

struct HeapSizes {
    string: i64,
    guid: i64,
    blob: i64,
}

/// Parsed streams by name (names are unique) and the metadata version.
struct ParsedStreams {
    streams: BTreeMap<String, MetadataStream>,
    version: String,
}

fn read_metadata_streams(
    bytes: &[u8],
    root_offset: i64,
    budget: &mut ManagedDecodeBudget,
) -> Result<ParsedStreams, ManagedReaderFailure> {
    if read_u32_at(bytes, 0)? != 0x424a_5342 {
        return Err(managed_failure(
            "invalid-metadata-root",
            "metadata.signature",
            "CLI metadata signature is not BSJB",
            Some(root_offset as u64),
        ));
    }
    let version_length = read_u32_at(bytes, 12)? as i64;
    require_range(bytes, root_offset, 16, version_length, "metadata.version")?;
    let version_bytes = &bytes[16..(16 + version_length) as usize];
    let zero = version_bytes.iter().position(|&byte| byte == 0);
    let decoded_version_length = zero.map(|z| z as i64).unwrap_or(version_bytes.len() as i64);
    budget.reserve_string(decoded_version_length, Some((root_offset + 16) as u64))?;
    let version =
        String::from_utf8_lossy(&version_bytes[..decoded_version_length as usize]).into_owned();
    let mut cursor = align4(16 + version_length);
    require_range(bytes, root_offset, cursor, 4, "metadata.stream-count")?;
    let stream_count = read_u16_at(bytes, cursor + 2)?;
    if stream_count == 0 || stream_count > 64 {
        return Err(managed_failure(
            "invalid-stream",
            "metadata.stream-count",
            "Metadata stream count is outside the admitted range",
            Some((root_offset + cursor + 2) as u64),
        ));
    }
    cursor += 4;
    let mut streams = BTreeMap::new();
    for _ in 0..stream_count {
        require_range(bytes, root_offset, cursor, 8, "metadata.stream-header")?;
        let relative_offset = read_u32_at(bytes, cursor)? as i64;
        let stream_size = read_u32_at(bytes, cursor + 4)? as i64;
        let (name, next) = read_stream_name(bytes, root_offset, cursor + 8)?;
        if streams.contains_key(&name) {
            return Err(managed_failure(
                "invalid-stream",
                "metadata.stream-header",
                format!("Duplicate metadata stream {name}"),
                Some((root_offset + cursor) as u64),
            ));
        }
        require_range(
            bytes,
            root_offset,
            relative_offset,
            stream_size,
            &format!("metadata.{name}"),
        )?;
        streams.insert(
            name,
            MetadataStream {
                offset: root_offset + relative_offset,
                size: stream_size,
            },
        );
        cursor = next;
    }
    Ok(ParsedStreams { streams, version })
}

struct ParsedTablesHeader {
    table_bytes_offset: i64,
    table_bytes_len: i64,
    tables_offset: i64,
    heaps: HeapSizes,
    valid: u64,
    heap_byte6: u8,
}

const SUPPORTED_TABLE_MASK: u64 = (1u64 << 45) - 1;

fn read_tables_header(
    artifact: &[u8],
    streams: &ParsedStreams,
) -> Result<ParsedTablesHeader, ManagedReaderFailure> {
    let tables_stream = match stream_by_name(&streams.streams, &["#~", "#-"]) {
        Some(stream) => stream,
        None => {
            return Err(managed_failure(
                "missing-stream",
                "metadata.tables",
                "Required metadata table stream #~ or #- is absent",
                None,
            ));
        }
    };
    let tables_offset = tables_stream.offset;
    let table_bytes_len = tables_stream.size;
    // `requireRange(tableBytes, tablesStream.offset, 0, 24, ...)`: tableBytes is
    // artifact.subarray(offset, offset+size); its length is size, base offset is
    // the stream offset.
    if table_bytes_len < 24 {
        return Err(managed_failure(
            "invalid-metadata-root",
            "metadata.tables-header",
            "metadata.tables-header leaves the metadata byte range",
            Some(tables_offset as u64),
        ));
    }
    let heap_byte6 = artifact
        .get((tables_offset + 6) as usize)
        .copied()
        .unwrap_or(0);
    let heaps = HeapSizes {
        string: if (heap_byte6 & 0x01) == 0 { 2 } else { 4 },
        guid: if (heap_byte6 & 0x02) == 0 { 2 } else { 4 },
        blob: if (heap_byte6 & 0x04) == 0 { 2 } else { 4 },
    };
    let valid = read_u64(artifact, (tables_offset + 8) as usize).map_err(root_internal)?;
    if (valid & !SUPPORTED_TABLE_MASK) != 0 {
        return Err(managed_failure(
            "invalid-tables",
            "metadata.valid-mask",
            "Metadata valid mask names unsupported tables outside the admitted ECMA-335 range",
            Some((tables_offset + 8) as u64),
        ));
    }
    Ok(ParsedTablesHeader {
        table_bytes_offset: tables_offset,
        table_bytes_len,
        tables_offset,
        heaps,
        valid,
        heap_byte6,
    })
}

fn read_row_counts(
    artifact: &[u8],
    header: &ParsedTablesHeader,
) -> Result<Vec<i64>, ManagedReaderFailure> {
    let mut row_counts = vec![0i64; METADATA_TABLE_NAMES.len()];
    let mut table_cursor = 24i64;
    for index in 0..METADATA_TABLE_NAMES.len() {
        if (header.valid & (1u64 << index)) == 0 {
            continue;
        }
        require_table_range(header, table_cursor, 4, "metadata.table-row-count")?;
        let count = read_u32(
            artifact,
            (header.table_bytes_offset + table_cursor) as usize,
        )
        .map_err(root_internal)? as i64;
        row_counts[index] = count;
        table_cursor += 4;
    }
    Ok(row_counts)
}

fn require_table_range(
    header: &ParsedTablesHeader,
    offset: i64,
    length: i64,
    scope: &str,
) -> Result<(), ManagedReaderFailure> {
    if offset < 0 || length < 0 || offset > header.table_bytes_len - length {
        return Err(managed_failure(
            "invalid-metadata-root",
            scope,
            format!("{scope} leaves the metadata byte range"),
            if offset >= 0 {
                Some((header.tables_offset + offset) as u64)
            } else {
                None
            },
        ));
    }
    Ok(())
}

fn build_metadata_tables(
    artifact: &[u8],
    header: &ParsedTablesHeader,
    row_counts: &[i64],
) -> Result<BTreeMap<usize, MetadataTableLayout>, ManagedReaderFailure> {
    let mut tables = BTreeMap::new();
    let table_size_closure = |index: usize| table_size(index, row_counts);
    let coded_size_closure = |name: &str| coded_size(name, row_counts);
    let context = RowSizeContext {
        table_size: &table_size_closure,
        coded_size: &coded_size_closure,
        string_size: header.heaps.string,
        guid_size: header.heaps.guid,
        blob_size: header.heaps.blob,
    };
    let mut table_cursor = 24i64;
    for index in 0..METADATA_TABLE_NAMES.len() {
        if (header.valid & (1u64 << index)) == 0 {
            continue;
        }
        table_cursor += 4;
    }
    // Honor an optional extra-data word after the row counts.
    if (header.heap_byte6 & 0x40) != 0 {
        if table_cursor > header.table_bytes_len - 4 {
            return Err(managed_failure(
                "invalid-metadata-root",
                "metadata.tables-extra-data",
                "Metadata tables extra-data word is truncated",
                Some((header.tables_offset + table_cursor) as u64),
            ));
        }
        table_cursor += 4;
    }
    for index in 0..METADATA_TABLE_NAMES.len() {
        let count = row_counts.get(index).copied().unwrap_or(0);
        if (header.valid & (1u64 << index)) == 0 {
            continue;
        }
        let size_of_row = compute_row_size(index, &context)?;
        let byte_length = count.checked_mul(size_of_row);
        let byte_length = match byte_length {
            Some(value) => value,
            None => {
                return Err(managed_failure(
                    "invalid-tables",
                    "metadata.tables",
                    "Metadata table byte size overflowed",
                    Some((header.tables_offset + table_cursor) as u64),
                ));
            }
        };
        require_table_range(header, table_cursor, byte_length, "metadata.table-data")?;
        let _ = artifact; // table extents are verified against the stream length
        tables.insert(
            index,
            MetadataTableLayout {
                index,
                name: table_name(index),
                row_count: count,
                row_size: size_of_row,
                offset: header.tables_offset + table_cursor,
            },
        );
        table_cursor += byte_length;
    }
    Ok(tables)
}

/// Parse ECMA-335 stream and table layout with checked byte extents.
pub fn read_managed_metadata_layout(
    artifact: &[u8],
    root_offset: i64,
    size: i64,
) -> Result<ManagedMetadataLayout, ManagedReaderFailure> {
    if size < 20 || root_offset < 0 || root_offset > artifact.len() as i64 - size {
        return Err(managed_failure(
            "invalid-metadata-root",
            "metadata.root",
            "CLI metadata directory leaves the artifact byte range",
            Some(root_offset as u64),
        ));
    }
    let bytes = &artifact[root_offset as usize..(root_offset + size) as usize];
    let mut budget = ManagedDecodeBudget::new();
    let parsed = read_metadata_streams(bytes, root_offset, &mut budget)?;
    let header = read_tables_header(artifact, &parsed)?;
    let row_counts = read_row_counts(artifact, &header)?;
    let tables = build_metadata_tables(artifact, &header, &row_counts)?;

    // `[...streams.keys()].sort()`: JS default string sort (UTF-16). Stream
    // names are printable ASCII, so byte order equals UTF-16 order.
    let mut stream_names: Vec<String> = parsed.streams.keys().cloned().collect();
    stream_names.sort();

    let layout = ManagedMetadataLayout {
        version: parsed.version,
        stream_names,
        strings: require_stream(&parsed.streams, "#Strings")?,
        guid: require_stream(&parsed.streams, "#GUID")?,
        blob: require_stream(&parsed.streams, "#Blob")?,
        user_strings: parsed.streams.get("#US").cloned(),
        tables,
        row_counts,
        string_index_size: header.heaps.string,
        guid_index_size: header.heaps.guid,
        blob_index_size: header.heaps.blob,
        budget: RefCell::new(budget),
    };
    Ok(layout)
}

/// `metadataRowOffset(layout, table, row)`: resolve a one-based row to its file
/// offset.
pub fn metadata_row_offset(
    layout: &ManagedMetadataLayout,
    table: usize,
    row: i64,
) -> Result<i64, ManagedReaderFailure> {
    match layout.table(table) {
        Some(descriptor) if row >= 1 && row <= descriptor.row_count => {
            Ok(descriptor.offset + (row - 1) * descriptor.row_size)
        }
        _ => Err(managed_failure(
            "invalid-row",
            format!("metadata.{}", table_name(table)),
            format!("Metadata row {row} is outside its table"),
            None,
        )),
    }
}
