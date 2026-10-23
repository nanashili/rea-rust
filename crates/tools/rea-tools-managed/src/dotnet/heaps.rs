//! Checked #Strings/#Blob/#US/#GUID heap reads and row cursors.
//!
//! Port of `src/dotnet/ManagedMetadataHeaps.ts`.

use sha2::{Digest, Sha256};

use super::budget::DigestAlgorithm;
use super::bytes::{read_u16, read_u32};
use super::failure::{ManagedParseIssue, ManagedReaderFailure, managed_failure};
use super::layout::{ManagedMetadataLayout, metadata_row_offset};

/// Cursor for checked fixed-width metadata row decoding.
pub struct MetadataRowCursor<'a> {
    bytes: &'a [u8],
    pub start: i64,
    end: i64,
    scope: String,
    offset: i64,
}

impl<'a> MetadataRowCursor<'a> {
    fn new(bytes: &'a [u8], start: i64, end: i64, scope: String) -> Self {
        Self {
            bytes,
            start,
            end,
            scope,
            offset: start,
        }
    }

    pub fn offset(&self) -> i64 {
        self.offset
    }

    pub fn read_u16(&mut self) -> Result<u16, ManagedReaderFailure> {
        self.require(2)?;
        let value = read_u16(self.bytes, self.offset as usize).map_err(|_| self.row_failure())?;
        self.offset += 2;
        Ok(value)
    }

    pub fn read_u32(&mut self) -> Result<u32, ManagedReaderFailure> {
        self.require(4)?;
        let value = read_u32(self.bytes, self.offset as usize).map_err(|_| self.row_failure())?;
        self.offset += 4;
        Ok(value)
    }

    pub fn read_index(&mut self, size: i64) -> Result<u32, ManagedReaderFailure> {
        if size == 2 {
            Ok(self.read_u16()? as u32)
        } else {
            self.read_u32()
        }
    }

    fn require(&self, length: i64) -> Result<(), ManagedReaderFailure> {
        if self.offset < self.start || self.offset > self.end - length {
            return Err(self.row_failure());
        }
        Ok(())
    }

    fn row_failure(&self) -> ManagedReaderFailure {
        managed_failure(
            "invalid-row",
            self.scope.clone(),
            format!("{} row ended before all declared columns", self.scope),
            Some(self.offset as u64),
        )
    }
}

enum PrefixedItem {
    Blob,
    UserString,
}

impl PrefixedItem {
    fn code(&self) -> &'static str {
        match self {
            PrefixedItem::Blob => "invalid-blob",
            PrefixedItem::UserString => "invalid-string",
        }
    }
    fn label(&self) -> &'static str {
        match self {
            PrefixedItem::Blob => "Metadata blob",
            PrefixedItem::UserString => "User string",
        }
    }
}

struct Compressed {
    length: i64,
    prefix: i64,
    minimal: bool,
}

fn compressed_length(
    bytes: &[u8],
    offset: i64,
    scope: &str,
    item: PrefixedItem,
) -> Result<Compressed, ManagedReaderFailure> {
    let require_prefix = |size: i64| -> Result<(), ManagedReaderFailure> {
        if offset < 0 || offset > bytes.len() as i64 - size {
            return Err(managed_failure(
                item.code(),
                scope,
                format!(
                    "{} length prefix leaves the artifact byte range",
                    item.label()
                ),
                if offset >= 0 {
                    Some(offset as u64)
                } else {
                    None
                },
            ));
        }
        Ok(())
    };
    require_prefix(1)?;
    let first = bytes.get(offset as usize).copied().unwrap_or(0) as i64;
    if (first & 0x80) == 0 {
        return Ok(Compressed {
            length: first,
            prefix: 1,
            minimal: true,
        });
    }
    if (first & 0xc0) == 0x80 {
        require_prefix(2)?;
        let length =
            ((first & 0x3f) << 8) | (bytes.get((offset + 1) as usize).copied().unwrap_or(0) as i64);
        return Ok(Compressed {
            length,
            prefix: 2,
            minimal: length >= 0x80,
        });
    }
    if (first & 0xe0) == 0xc0 {
        require_prefix(4)?;
        let length = (first & 0x1f) * 0x01_00_00_00
            + (bytes.get((offset + 1) as usize).copied().unwrap_or(0) as i64) * 0x01_00_00
            + (bytes.get((offset + 2) as usize).copied().unwrap_or(0) as i64) * 0x0100
            + (bytes.get((offset + 3) as usize).copied().unwrap_or(0) as i64);
        return Ok(Compressed {
            length,
            prefix: 4,
            minimal: length >= 0x4000,
        });
    }
    Err(managed_failure(
        item.code(),
        scope,
        format!("{} uses a reserved compressed-length prefix", item.label()),
        Some(offset as u64),
    ))
}

/// `readMetadataString`: read one UTF-8 value from #Strings within its extent.
pub fn read_metadata_string(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    index: u32,
    heap_extent: i64,
) -> Result<String, ManagedReaderFailure> {
    let index = index as i64;
    if index == 0 {
        return Ok(String::new());
    }
    if index < 0 || index >= layout.strings.size {
        return Err(managed_failure(
            "invalid-heap-index",
            "metadata.#Strings",
            "String heap index is outside #Strings",
            Some((layout.strings.offset + index.max(0)) as u64),
        ));
    }
    let start = layout.strings.offset + index;
    {
        let budget = layout.budget();
        if let Some(cached) = budget.cached_string(index as usize) {
            if cached.encoded_bytes as i64 <= heap_extent {
                return Ok(cached.value.clone());
            }
        }
    }
    let maximum = (layout.strings.offset + layout.strings.size).min(start + heap_extent + 1);
    let mut end = start;
    while end < maximum && bytes.get(end as usize).copied() != Some(0) {
        end += 1;
    }
    if end == maximum {
        return Err(managed_failure(
            "invalid-string",
            "metadata.#Strings",
            "String heap item has no terminator within #Strings",
            Some(start as u64),
        ));
    }
    layout
        .budget()
        .reserve_string(end - start, Some(start as u64))?;
    let slice = &bytes[start as usize..end as usize];
    match std::str::from_utf8(slice) {
        Ok(value) => {
            let value = value.to_string();
            layout
                .budget()
                .cache_string(index as usize, value.clone(), (end - start) as usize);
            Ok(value)
        }
        Err(_) => Err(managed_failure(
            "invalid-string",
            "metadata.#Strings",
            "String heap item is not valid UTF-8",
            Some(start as u64),
        )),
    }
}

/// `readMetadataBlob`: read one #Blob item while validating its extent.
pub fn read_metadata_blob<'a>(
    bytes: &'a [u8],
    layout: &ManagedMetadataLayout,
    index: u32,
    heap_extent: i64,
) -> Result<&'a [u8], ManagedReaderFailure> {
    let index = index as i64;
    if index == 0 {
        return Ok(&[]);
    }
    if index < 0 || index >= layout.blob.size {
        return Err(managed_failure(
            "invalid-heap-index",
            "metadata.#Blob",
            "Blob heap index is outside #Blob",
            Some((layout.blob.offset + index.max(0)) as u64),
        ));
    }
    let start = layout.blob.offset + index;
    let decoded = compressed_length(bytes, start, "metadata.#Blob", PrefixedItem::Blob)?;
    if decoded.length > heap_extent {
        return Err(managed_failure(
            "invalid-blob",
            "metadata.#Blob",
            "Blob length exceeds the admitted heap extent",
            Some(start as u64),
        ));
    }
    let content = start + decoded.prefix;
    if content > layout.blob.offset + layout.blob.size - decoded.length {
        return Err(managed_failure(
            "invalid-blob",
            "metadata.#Blob",
            "Blob heap item leaves #Blob",
            Some(start as u64),
        ));
    }
    Ok(&bytes[content as usize..(content + decoded.length) as usize])
}

/// The result of reading a #US literal: offset, decoded UTF-16 value, and any
/// conformance issues observed beside the readable literal.
pub struct UserStringRead {
    pub offset: i64,
    pub value: String,
    pub issues: Vec<ManagedParseIssue>,
}

/// `readMetadataUserString`: read the #US literal named by a `0x70` token.
///
/// Unpaired surrogates in the stored UTF-16LE cannot be represented by a Rust
/// `String`, so they are replaced with U+FFFD via `from_utf16_lossy`. This is
/// a documented representation deviation from the TS, which keeps unpaired
/// surrogates.
pub fn read_metadata_user_string(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    token: &str,
) -> Result<UserStringRead, ManagedReaderFailure> {
    let scope = format!("metadata.#US:{token}");
    let heap = match &layout.user_strings {
        Some(heap) => heap.clone(),
        None => {
            return Err(managed_failure(
                "missing-stream",
                scope,
                "ldstr references #US, but the metadata has no #US stream",
                None,
            ));
        }
    };
    let index = i64::from_str_radix(&token[4..], 16).unwrap_or(0);
    if index >= heap.size {
        return Err(managed_failure(
            "invalid-heap-index",
            scope,
            "ldstr operand does not name an item inside #US",
            Some((heap.offset + index) as u64),
        ));
    }
    let start = heap.offset + index;
    let decoded = compressed_length(bytes, start, &scope, PrefixedItem::UserString)?;
    let content = start + decoded.prefix;
    if content > heap.offset + heap.size - decoded.length {
        return Err(managed_failure(
            "invalid-string",
            scope,
            "User string leaves #US",
            Some(start as u64),
        ));
    }
    // A wider length prefix than needed is reported like the flag rather than
    // discarding the literal; admitted only on returning paths.
    let conformance =
        |layout: &ManagedMetadataLayout| -> Result<Vec<ManagedParseIssue>, ManagedReaderFailure> {
            if decoded.minimal {
                return Ok(Vec::new());
            }
            layout.budget().reserve(512, Some(start as u64))?;
            Ok(vec![ManagedParseIssue {
                code: "invalid-string",
                scope: scope.clone(),
                offset: Some(start as u64),
                detail: format!(
                    "User string length {} uses a {}-byte prefix wider than ECMA-335 II.23.2 assigns; readable UTF-16 is preserved and runtime acceptance is not assessed",
                    decoded.length, decoded.prefix
                ),
            }])
        };
    // ECMA-335 II.24.2.4: offset 0 is the heap's empty entry.
    if index == 0 {
        if decoded.length == 0 {
            return Ok(UserStringRead {
                offset: start,
                value: String::new(),
                issues: conformance(layout)?,
            });
        }
        return Err(managed_failure(
            "invalid-string",
            scope,
            format!(
                "#US offset 0 is the reserved empty entry, but it encodes {} byte(s)",
                decoded.length
            ),
            Some(start as u64),
        ));
    }
    if decoded.length % 2 != 1 {
        return Err(managed_failure(
            "invalid-string",
            scope,
            "User string length is not UTF-16 code units plus one terminal flag byte",
            Some(start as u64),
        ));
    }
    let units = (decoded.length - 1) / 2;
    layout.budget().reserve_string(units, Some(start as u64))?;
    let mut expected_flag = 0u8;
    for unit_index in 0..units {
        let unit = read_u16(bytes, (content + unit_index * 2) as usize)
            .map_err(|_| user_internal(&scope))?;
        if unit > 0xff
            || (0x01..=0x08).contains(&unit)
            || (0x0e..=0x1f).contains(&unit)
            || unit == 0x27
            || unit == 0x2d
            || unit == 0x7f
        {
            expected_flag = 1;
            break;
        }
    }
    let flag_offset = content + units * 2;
    let actual_flag = bytes.get(flag_offset as usize).copied();
    let mut issues = conformance(layout)?;
    if actual_flag != Some(expected_flag) {
        layout.budget().reserve(512, Some(flag_offset as u64))?;
        let actual = actual_flag.map(|value| value as i64);
        issues.push(ManagedParseIssue {
            code: "invalid-string",
            scope: scope.clone(),
            offset: Some(flag_offset as u64),
            detail: format!(
                "User string terminal flag {} differs from ECMA-335 II.24.2.4 value {}; readable UTF-16 is preserved and runtime acceptance is not assessed",
                js_number(actual),
                expected_flag
            ),
        });
    }
    // UTF-16LE code units -> String (lossy for unpaired surrogates).
    let unit_slice = &bytes[content as usize..flag_offset as usize];
    let mut units16 = Vec::with_capacity(unit_slice.len() / 2);
    for chunk in unit_slice.chunks_exact(2) {
        units16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let value = String::from_utf16_lossy(&units16);
    Ok(UserStringRead {
        offset: start,
        value,
        issues,
    })
}

/// `String(actualFlag)` where `actualFlag` may be `undefined` -> `"undefined"`.
fn js_number(value: Option<i64>) -> String {
    match value {
        Some(number) => number.to_string(),
        None => "undefined".to_string(),
    }
}

fn user_internal(scope: &str) -> ManagedReaderFailure {
    managed_failure(
        "invalid-string",
        scope.to_string(),
        "User string read left the artifact byte range",
        None,
    )
}

/// `readMetadataGuid`: read one conventional GUID from the one-based #GUID heap.
pub fn read_metadata_guid(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    index: u32,
) -> Result<Option<String>, ManagedReaderFailure> {
    let index = index as i64;
    if index == 0 {
        return Ok(None);
    }
    let relative = (index - 1) * 16;
    if relative < 0 || relative > layout.guid.size - 16 {
        return Err(managed_failure(
            "invalid-guid",
            "metadata.#GUID",
            "GUID heap index is outside #GUID",
            Some((layout.guid.offset + relative.max(0)) as u64),
        ));
    }
    let offset = layout.guid.offset + relative;
    let read_u32_here =
        |at: i64| read_u32(bytes, at as usize).map_err(|_| user_internal("metadata.#GUID"));
    let read_u16_here =
        |at: i64| read_u16(bytes, at as usize).map_err(|_| user_internal("metadata.#GUID"));
    let part1 = format!("{:08x}", read_u32_here(offset)?);
    let part2 = format!("{:04x}", read_u16_here(offset + 4)?);
    let part3 = format!("{:04x}", read_u16_here(offset + 6)?);
    let part4 = hex(&bytes[(offset + 8) as usize..(offset + 10) as usize]);
    let part5 = hex(&bytes[(offset + 10) as usize..(offset + 16) as usize]);
    Ok(Some(format!("{part1}-{part2}-{part3}-{part4}-{part5}")))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `metadataToken(table, row)`: an exact build-local token.
pub fn metadata_token(table: usize, row: i64) -> String {
    format!("0x{:08x}", table as i64 * 0x01_00_00_00 + row)
}

/// `sha256Bytes`: lowercase hex SHA-256 of bytes.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// `metadataRowCursor(bytes, layout, table, row)`.
pub fn metadata_row_cursor<'a>(
    bytes: &'a [u8],
    layout: &ManagedMetadataLayout,
    table: usize,
    row: i64,
) -> Result<MetadataRowCursor<'a>, ManagedReaderFailure> {
    let start = metadata_row_offset(layout, table, row)?;
    let descriptor = match layout.table(table) {
        Some(descriptor) => descriptor.clone(),
        None => {
            return Err(managed_failure(
                "invalid-row",
                format!("metadata.{table}"),
                "Metadata table is absent",
                Some(start as u64),
            ));
        }
    };
    layout
        .budget()
        .reserve_row(table, row as usize, start as u64)?;
    Ok(MetadataRowCursor::new(
        bytes,
        start,
        start + descriptor.row_size,
        format!("metadata.{}", descriptor.name),
    ))
}

/// `metadataCodedToken`: decode a coded index to a token, or `None`.
pub fn metadata_coded_token(
    raw: u32,
    bits: u32,
    tables: &[Option<usize>],
    row_counts: &[i64],
) -> Option<String> {
    if raw == 0 {
        return None;
    }
    let tag = (raw & ((1u32 << bits) - 1)) as usize;
    let row = (raw >> bits) as i64;
    let table = tables.get(tag).copied().flatten()?;
    if row == 0 || row > row_counts.get(table).copied().unwrap_or(0) {
        None
    } else {
        Some(metadata_token(table, row))
    }
}

/// `metadataCodedTokenInvalidReason`.
pub fn metadata_coded_token_invalid_reason(
    raw: u32,
    bits: u32,
    tables: &[Option<usize>],
    row_counts: &[i64],
) -> Option<String> {
    if raw == 0 {
        return None;
    }
    let tag = (raw & ((1u32 << bits) - 1)) as usize;
    let row = (raw >> bits) as i64;
    let table = match tables.get(tag).copied().flatten() {
        Some(table) => table,
        None => return Some(format!("coded index tag {tag} is not defined")),
    };
    if row == 0 {
        return Some(format!("coded index selects row zero in table {table}"));
    }
    let count = row_counts.get(table).copied().unwrap_or(0);
    if row > count {
        Some(format!(
            "coded index selects row {row} in table {table}, which has {count} rows"
        ))
    } else {
        None
    }
}

/// `digest(bytes, algorithm)` via the layout's shared budget, keyed by the
/// slice's position within `source` and its length (stable range identity).
pub fn budget_digest(
    layout: &ManagedMetadataLayout,
    source: &[u8],
    slice: &[u8],
    algorithm: DigestAlgorithm,
) -> Result<String, ManagedReaderFailure> {
    let key = range_key(source, slice);
    layout.budget().digest(slice, key.as_deref(), algorithm)
}

/// The TS digest cache identity of `slice`: `byteOffset:byteLength` within the
/// artifact bytes when the slice is a view of `source`, or `None` for bytes
/// with their own backing store (TS `Buffer.alloc(0)` for a null #Blob index),
/// which never share a cached digest.
pub fn range_key(source: &[u8], slice: &[u8]) -> Option<String> {
    let base = source.as_ptr() as usize;
    let child = slice.as_ptr() as usize;
    let inside = child >= base
        && child
            .checked_add(slice.len())
            .is_some_and(|end| end <= base + source.len());
    inside.then(|| format!("{}:{}", child - base, slice.len()))
}
