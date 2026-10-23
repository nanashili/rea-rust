//! Minimal ECMA-335 managed-metadata reader for Unity AssemblyRef witnesses.
//!
//! Faithful subset port of the TypeScript managed reader
//! (`src/dotnet/ManagedMetadataLayout.ts`, `ManagedMetadataRowSizes.ts`,
//! `ManagedMetadataHeaps.ts`, `ManagedMetadataInventoryRows.ts`,
//! `ManagedDecodeBudget.ts`, `ManagedReaderFailure.ts`). Only the pieces the
//! desktop Unity-assembly-reference witness needs are ported: stream/table
//! layout, row-size computation, the row cursor, `#Strings` reading,
//! `metadataToken`, `metadataRowOffset`, the per-layout decode budget, and
//! `readAssemblyReferenceName`. Decoding never follows blobs/hashes.

use std::collections::{BTreeMap, HashMap, HashSet};

use sha2::{Digest, Sha256};

/// Per-inspection representation capacity (`MAX_METADATA_REPRESENTATION_BYTES`).
const MAX_METADATA_REPRESENTATION_BYTES: u64 = 64 * 1024 * 1024;

/// A managed parse failure classified like `ManagedReaderFailure`.
#[derive(Debug)]
pub(crate) struct ManagedFailure {
    /// `true` only for `resource-limit` (TS maps this to reason `"limit"`).
    pub resource_limit: bool,
    pub message: String,
}

impl ManagedFailure {
    fn new(resource_limit: bool, message: impl Into<String>) -> Self {
        Self {
            resource_limit,
            message: message.into(),
        }
    }
}

type ManagedResult<T> = Result<T, ManagedFailure>;

fn failure<T>(message: impl Into<String>) -> ManagedResult<T> {
    Err(ManagedFailure::new(false, message))
}

fn resource_limit<T>(message: impl Into<String>) -> ManagedResult<T> {
    Err(ManagedFailure::new(true, message))
}

const METADATA_TABLE_COUNT: usize = 45;

// (The ECMA-335 table-name list lives in the TS oracle; the row-size and
// coded-index logic below reference tables by index, not by name.)
#[allow(dead_code)]
const _METADATA_TABLE_NAMES: [&str; METADATA_TABLE_COUNT] = [
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

/// One coded-index descriptor (`CODED_INDEXES`).
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
        _ => unreachable!("unknown coded index name"),
    }
}

/// `SUPPORTED_TABLE_MASK = (1n << 45n) - 1n`.
fn supported_table_mask() -> u64 {
    (1u64 << METADATA_TABLE_COUNT) - 1
}

fn align4(value: usize) -> usize {
    value.div_ceil(4) * 4
}

/// `tableSize(index, rows)`.
fn table_size(index: usize, rows: &[u32]) -> u32 {
    if rows.get(index).copied().unwrap_or(0) < 0x1_0000 {
        2
    } else {
        4
    }
}

/// `codedSize(name, rowCounts)`.
fn coded_size(name: &str, rows: &[u32]) -> u32 {
    let descriptor = coded_index(name);
    let mut maximum = 0u32;
    for table in descriptor.tables {
        maximum = maximum.max(rows.get(*table).copied().unwrap_or(0));
    }
    if (maximum as u64) < (1u64 << (16 - descriptor.bits)) {
        2
    } else {
        4
    }
}

/// `computeRowSize(table, context)` — the ECMA-335 row-size table.
fn compute_row_size(table: usize, rows: &[u32], s: u32, g: u32, b: u32) -> ManagedResult<u32> {
    let t = |index: usize| table_size(index, rows);
    let c = |name: &str| coded_size(name, rows);
    let size = match table {
        0 => 2 + s + g * 3,
        1 => c("ResolutionScope") + s * 2,
        2 => 4 + s * 2 + c("TypeDefOrRef") + t(3).max(t(4)) + t(5).max(t(6)),
        3 => t(4),
        4 => 2 + s + b,
        5 => t(6),
        6 => 8 + s + b + t(8),
        7 => t(8),
        8 => 4 + s,
        9 => t(2) + c("TypeDefOrRef"),
        10 => c("MemberRefParent") + s + b,
        11 => 2 + c("HasConstant") + b,
        12 => c("HasCustomAttribute") + c("CustomAttributeType") + b,
        13 => c("HasFieldMarshal") + b,
        14 => 2 + c("HasDeclSecurity") + b,
        15 => 6 + t(2),
        16 => 4 + t(4),
        17 => b,
        18 => t(2) + t(20),
        19 => t(20),
        20 => 2 + s + c("TypeDefOrRef"),
        21 => t(2) + t(23),
        22 => t(23),
        23 => 2 + s + b,
        24 => 2 + t(6) + c("HasSemantics"),
        25 => t(2) + c("MethodDefOrRef") * 2,
        26 => s,
        27 => b,
        28 => 2 + c("MemberForwarded") + s + t(26),
        29 => 4 + t(4),
        30 => 8,
        31 => 4,
        32 => 16 + b + s * 2,
        33 => 4,
        34 => 12,
        35 => 12 + b * 2 + s * 2,
        36 => 4 + t(35),
        37 => 12 + t(35),
        38 => 4 + s + b,
        39 => 8 + s * 2 + c("Implementation"),
        40 => 8 + s + c("Implementation"),
        41 => t(2) * 2,
        42 => 4 + c("TypeOrMethodDef") + s,
        43 => c("MethodDefOrRef") + b,
        44 => t(42) + c("TypeDefOrRef"),
        _ => return failure(format!("Metadata table {table} is unsupported")),
    };
    Ok(size)
}

/// Per-layout decode budget (`ManagedDecodeBudget`), scoped to one layout.
pub(crate) struct DecodeBudget {
    remaining: u64,
    rows: HashMap<usize, HashSet<u32>>,
    strings: HashMap<u32, (String, u64)>,
}

impl DecodeBudget {
    fn new() -> Self {
        Self {
            remaining: MAX_METADATA_REPRESENTATION_BYTES,
            rows: HashMap::new(),
            strings: HashMap::new(),
        }
    }

    fn reserve(&mut self, bytes: u64) -> ManagedResult<()> {
        if bytes > self.remaining {
            return resource_limit(format!(
                "Managed metadata exceeds the {MAX_METADATA_REPRESENTATION_BYTES} byte representation budget"
            ));
        }
        self.remaining -= bytes;
        Ok(())
    }

    /// `reserveString`: JSON uses at most six bytes per UTF-16 unit; UTF-8
    /// cannot decode to more UTF-16 units than bytes.
    fn reserve_string(&mut self, encoded_bytes: u64) -> ManagedResult<()> {
        self.reserve(encoded_bytes * 6 + 2)
    }

    /// `reserveRow`: one reservation per physical row.
    fn reserve_row(&mut self, table: usize, row: u32) -> ManagedResult<()> {
        if self.rows.get(&table).is_some_and(|set| set.contains(&row)) {
            return Ok(());
        }
        self.reserve(256)?;
        self.rows.entry(table).or_default().insert(row);
        Ok(())
    }
}

/// One metadata stream (`MetadataStream`): offsets are absolute file offsets.
#[derive(Clone)]
struct MetadataStream {
    offset: usize,
    size: usize,
}

/// One admitted metadata table (`MetadataTableLayout`).
#[derive(Clone)]
struct TableLayout {
    row_count: u32,
    row_size: u32,
    /// Absolute file offset of the first row.
    offset: usize,
}

/// Parsed ECMA-335 stream/table layout (`ManagedMetadataLayout` subset).
pub(crate) struct Layout {
    strings: MetadataStream,
    tables: BTreeMap<usize, TableLayout>,
    string_index_size: u32,
    blob_index_size: u32,
    budget: DecodeBudget,
}

/// `requireRange`: a range stays inside `bytes`, which begin at file `base`.
fn require_range(len: usize, offset: usize, length: usize, scope: &str) -> ManagedResult<()> {
    if length > len || offset > len - length {
        return failure(format!("{scope} leaves the metadata byte range"));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> ManagedResult<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
        .ok_or_else(|| ManagedFailure::new(false, "metadata read out of range"))
}

fn read_u32(bytes: &[u8], offset: usize) -> ManagedResult<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        .ok_or_else(|| ManagedFailure::new(false, "metadata read out of range"))
}

fn read_u64(bytes: &[u8], offset: usize) -> ManagedResult<u64> {
    bytes
        .get(offset..offset + 8)
        .map(|slice| {
            u64::from_le_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ])
        })
        .ok_or_else(|| ManagedFailure::new(false, "metadata read out of range"))
}

/// `readStreamName`: bounded printable-ASCII name with 4-byte alignment.
fn read_stream_name(bytes: &[u8], offset: usize) -> ManagedResult<(String, usize)> {
    let end_limit = bytes.len().min(offset + 32);
    let mut end = offset;
    while end < end_limit && bytes[end] != 0 {
        end += 1;
    }
    if end == end_limit {
        return failure("Metadata stream name is missing a bounded terminator");
    }
    let name_bytes = &bytes[offset..end];
    if name_bytes.iter().any(|byte| *byte < 0x20 || *byte > 0x7e) {
        return failure("Metadata stream name is not printable ASCII");
    }
    let name = String::from_utf8_lossy(name_bytes).into_owned();
    Ok((name, align4(end + 1)))
}

/// `readMetadataStreams`: BSJB signature, version, stream headers.
fn read_metadata_streams(
    bytes: &[u8],
    root_offset: usize,
    budget: &mut DecodeBudget,
) -> ManagedResult<BTreeMap<String, MetadataStream>> {
    if read_u32(bytes, 0)? != 0x424a_5342 {
        return failure("CLI metadata signature is not BSJB");
    }
    let version_length = read_u32(bytes, 12)? as usize;
    require_range(bytes.len(), 16, version_length, "metadata.version")?;
    let version_bytes = &bytes[16..16 + version_length];
    let zero = version_bytes.iter().position(|byte| *byte == 0);
    let decoded_version_length = zero.unwrap_or(version_length);
    budget.reserve_string(decoded_version_length as u64)?;

    let mut cursor = align4(16 + version_length);
    require_range(bytes.len(), cursor, 4, "metadata.stream-count")?;
    let stream_count = read_u16(bytes, cursor + 2)?;
    if stream_count == 0 || stream_count > 64 {
        return failure("Metadata stream count is outside the admitted range");
    }
    cursor += 4;

    let mut streams: BTreeMap<String, MetadataStream> = BTreeMap::new();
    for _ in 0..stream_count {
        require_range(bytes.len(), cursor, 8, "metadata.stream-header")?;
        let relative_offset = read_u32(bytes, cursor)? as usize;
        let stream_size = read_u32(bytes, cursor + 4)? as usize;
        let (name, next) = read_stream_name(bytes, cursor + 8)?;
        if streams.contains_key(&name) {
            return failure(format!("Duplicate metadata stream {name}"));
        }
        require_range(
            bytes.len(),
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
    Ok(streams)
}

struct HeapSizes {
    string: u32,
    guid: u32,
    blob: u32,
}

struct TablesHeader {
    tables_offset: usize,
    heaps: HeapSizes,
    valid: u64,
    heap_flags: u8,
}

/// `readTablesHeader`: heap sizes, valid mask and tables-stream location.
fn read_tables_header(
    artifact: &[u8],
    streams: &BTreeMap<String, MetadataStream>,
) -> ManagedResult<(TablesHeader, usize, usize)> {
    let tables_stream = streams
        .get("#~")
        .or_else(|| streams.get("#-"))
        .ok_or_else(|| {
            ManagedFailure::new(false, "Required metadata table stream #~ or #- is absent")
        })?;
    let stream_start = tables_stream.offset;
    let stream_end = tables_stream.offset + tables_stream.size;
    let table_bytes = artifact
        .get(stream_start..stream_end)
        .ok_or_else(|| ManagedFailure::new(false, "metadata tables stream out of range"))?;
    require_range(table_bytes.len(), 0, 24, "metadata.tables-header")?;
    let heap_flags = table_bytes.get(6).copied().unwrap_or(0);
    let heaps = HeapSizes {
        string: if heap_flags & 0x01 == 0 { 2 } else { 4 },
        guid: if heap_flags & 0x02 == 0 { 2 } else { 4 },
        blob: if heap_flags & 0x04 == 0 { 2 } else { 4 },
    };
    let valid = read_u64(table_bytes, 8)?;
    if valid & !supported_table_mask() != 0 {
        return failure(
            "Metadata valid mask names unsupported tables outside the admitted ECMA-335 range",
        );
    }
    Ok((
        TablesHeader {
            tables_offset: stream_start,
            heaps,
            valid,
            heap_flags,
        },
        stream_start,
        stream_end,
    ))
}

/// `readRowCounts`.
fn read_row_counts(table_bytes: &[u8], valid: u64) -> ManagedResult<Vec<u32>> {
    let mut row_counts = vec![0u32; METADATA_TABLE_COUNT];
    let mut cursor = 24usize;
    for (index, slot) in row_counts.iter_mut().enumerate() {
        if valid & (1u64 << index) == 0 {
            continue;
        }
        require_range(table_bytes.len(), cursor, 4, "metadata.table-row-count")?;
        *slot = read_u32(table_bytes, cursor)?;
        cursor += 4;
    }
    Ok(row_counts)
}

/// `buildMetadataTables`.
fn build_tables(
    table_bytes: &[u8],
    tables_offset: usize,
    row_counts: &[u32],
    heaps: &HeapSizes,
    valid: u64,
    heap_flags: u8,
) -> ManagedResult<BTreeMap<usize, TableLayout>> {
    let mut tables: BTreeMap<usize, TableLayout> = BTreeMap::new();
    let mut cursor = 24usize;
    for index in 0..METADATA_TABLE_COUNT {
        if valid & (1u64 << index) != 0 {
            cursor += 4;
        }
    }
    if heap_flags & 0x40 != 0 {
        if cursor > table_bytes.len().saturating_sub(4) {
            return failure("Metadata tables extra-data word is truncated");
        }
        cursor += 4;
    }
    for index in 0..METADATA_TABLE_COUNT {
        if valid & (1u64 << index) == 0 {
            continue;
        }
        let count = row_counts.get(index).copied().unwrap_or(0);
        let row_size = compute_row_size(index, row_counts, heaps.string, heaps.guid, heaps.blob)?;
        let byte_length = count as usize * row_size as usize;
        require_range(
            table_bytes.len(),
            cursor,
            byte_length,
            "metadata.table-data",
        )?;
        tables.insert(
            index,
            TableLayout {
                row_count: count,
                row_size,
                offset: tables_offset + cursor,
            },
        );
        cursor += byte_length;
    }
    Ok(tables)
}

impl Layout {
    /// `readManagedMetadataLayout(artifact, rootOffset, size)`.
    pub(crate) fn read(artifact: &[u8], root_offset: usize, size: usize) -> ManagedResult<Layout> {
        if size < 20 || root_offset > artifact.len().saturating_sub(size) {
            return failure("CLI metadata directory leaves the artifact byte range");
        }
        let bytes = &artifact[root_offset..root_offset + size];
        let mut budget = DecodeBudget::new();
        let streams = read_metadata_streams(bytes, root_offset, &mut budget)?;
        let (header, stream_start, stream_end) = read_tables_header(artifact, &streams)?;
        let table_bytes = &artifact[stream_start..stream_end];
        let row_counts = read_row_counts(table_bytes, header.valid)?;
        let tables = build_tables(
            table_bytes,
            header.tables_offset,
            &row_counts,
            &header.heaps,
            header.valid,
            header.heap_flags,
        )?;
        let strings = streams.get("#Strings").cloned().ok_or_else(|| {
            ManagedFailure::new(false, "Required metadata stream #Strings is absent")
        })?;
        Ok(Layout {
            strings,
            tables,
            string_index_size: header.heaps.string,
            blob_index_size: header.heaps.blob,
            budget,
        })
    }

    fn table(&self, index: usize) -> Option<&TableLayout> {
        self.tables.get(&index)
    }

    /// `metadataRowOffset(layout, table, row)` (one-based row).
    fn row_offset(&self, table: usize, row: u32) -> ManagedResult<usize> {
        let descriptor = self.table(table);
        match descriptor {
            Some(descriptor) if row >= 1 && row <= descriptor.row_count => {
                Ok(descriptor.offset + (row as usize - 1) * descriptor.row_size as usize)
            }
            _ => failure(format!("Metadata row {row} is outside its table")),
        }
    }
}

/// `metadataToken(table, row)`.
fn metadata_token(table: usize, row: u32) -> String {
    format!("0x{:08x}", (table as u64) * 0x0100_0000 + row as u64)
}

/// Checked fixed-width row cursor (`MetadataRowCursor`).
struct RowCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    end: usize,
}

impl<'a> RowCursor<'a> {
    fn read_u16(&mut self) -> ManagedResult<u16> {
        self.require(2)?;
        let value = read_u16(self.bytes, self.offset)?;
        self.offset += 2;
        Ok(value)
    }

    fn read_u32(&mut self) -> ManagedResult<u32> {
        self.require(4)?;
        let value = read_u32(self.bytes, self.offset)?;
        self.offset += 4;
        Ok(value)
    }

    fn read_index(&mut self, size: u32) -> ManagedResult<u32> {
        if size == 2 {
            Ok(self.read_u16()? as u32)
        } else {
            self.read_u32()
        }
    }

    fn require(&self, length: usize) -> ManagedResult<()> {
        if self.offset > self.end.saturating_sub(length) {
            return failure("metadata row ended before all declared columns");
        }
        Ok(())
    }
}

/// `metadataRowCursor(bytes, layout, table, row)`.
fn row_cursor<'a>(
    artifact: &'a [u8],
    layout: &mut Layout,
    table: usize,
    row: u32,
) -> ManagedResult<RowCursor<'a>> {
    let start = layout.row_offset(table, row)?;
    let row_size = layout
        .table(table)
        .map(|descriptor| descriptor.row_size as usize)
        .ok_or_else(|| ManagedFailure::new(false, "Metadata table is absent"))?;
    layout.budget.reserve_row(table, row)?;
    Ok(RowCursor {
        bytes: artifact,
        offset: start,
        end: start + row_size,
    })
}

/// `readMetadataString(bytes, layout, index, heapExtent)`.
fn read_metadata_string(
    artifact: &[u8],
    layout: &mut Layout,
    index: u32,
    heap_extent: usize,
) -> ManagedResult<String> {
    if index == 0 {
        return Ok(String::new());
    }
    let index = index as usize;
    if index >= layout.strings.size {
        return failure("String heap index is outside #Strings");
    }
    let start = layout.strings.offset + index;
    if let Some((value, encoded)) = layout.budget.strings.get(&(index as u32))
        && *encoded <= heap_extent as u64
    {
        return Ok(value.clone());
    }
    let maximum = (layout.strings.offset + layout.strings.size).min(start + heap_extent + 1);
    let mut end = start;
    while end < maximum && artifact.get(end).copied().unwrap_or(0) != 0 {
        end += 1;
    }
    if end == maximum {
        return failure("String heap item has no terminator within #Strings");
    }
    layout.budget.reserve_string((end - start) as u64)?;
    let slice = &artifact[start..end];
    match std::str::from_utf8(slice) {
        Ok(value) => {
            let value = value.to_owned();
            layout
                .budget
                .strings
                .insert(index as u32, (value.clone(), (end - start) as u64));
            Ok(value)
        }
        Err(_) => failure("String heap item is not valid UTF-8"),
    }
}

/// One AssemblyRef name/token/offset witness (`readAssemblyReferenceName`).
pub(crate) struct AssemblyReferenceName {
    pub name: String,
    pub token: String,
    pub row_offset: usize,
}

/// `layout.table(35)?.rowCount ?? 0` — the AssemblyRef table row count.
pub(crate) fn assembly_reference_count(layout: &Layout) -> u32 {
    layout.table(35).map(|table| table.row_count).unwrap_or(0)
}

/// `readAssemblyReferenceName(bytes, layout, row, layout.strings.size)`.
pub(crate) fn read_assembly_reference_name(
    artifact: &[u8],
    layout: &mut Layout,
    row: u32,
) -> ManagedResult<AssemblyReferenceName> {
    let heap_extent = layout.strings.size;
    let (string_index_size, blob_index_size) = (layout.string_index_size, layout.blob_index_size);
    let name_index = {
        let mut cursor = row_cursor(artifact, layout, 35, row)?;
        // version: four u16 columns.
        cursor.read_u16()?;
        cursor.read_u16()?;
        cursor.read_u16()?;
        cursor.read_u16()?;
        // flags: u32.
        cursor.read_u32()?;
        // public-key-or-token blob index.
        cursor.read_index(blob_index_size)?;
        // name string index.
        cursor.read_index(string_index_size)?
    };
    let name = read_metadata_string(artifact, layout, name_index, heap_extent)?;
    let row_offset = layout.row_offset(35, row)?;
    Ok(AssemblyReferenceName {
        name,
        token: metadata_token(35, row),
        row_offset,
    })
}

/// Shared SHA-256 hex digest helper (used elsewhere in the family port).
#[allow(dead_code)]
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
