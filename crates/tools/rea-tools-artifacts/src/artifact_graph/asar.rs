//! Self-contained ASAR (Electron archive) classification probe and reader.
//!
//! Compatibility owners: `src/artifacts/AsarHeader.ts` (Pickle extents and the
//! bounded signature probe), `src/artifacts/AsarListing.ts` (header tree
//! expansion and budgets) and `src/artifacts/AsarArtifactReader.ts` (packed and
//! unpacked member ranges). An ASAR file is a two-Pickle prefix (`4` + the
//! JSON header pickle) followed by the packed payload; member `offset` values
//! are relative to `8 + headerBytes`.
use super::classify::AsarProbe;
use super::reader::{ArtifactEntry, ArtifactReader, ArtifactTraversalOmission, ReaderFailure};
use rea_core::cancellation::Cancellation;
use serde_json::Value;

const MAX_ASAR_HEADER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ASAR_HEADER_PROBE_BYTES: u64 = MAX_ASAR_HEADER_BYTES + 8;
const MAX_LISTING_BYTES: u64 = 64 * 1024 * 1024;

struct Extents {
    header_bytes: u64,
    json_bytes: u64,
}

/// `parseAsarHeaderExtents` over the fixed 16-byte prefix. `archive_bytes` is
/// the observed container size when known.
fn parse_extents(prefix: &[u8], archive_bytes: Option<u64>) -> Result<Extents, ReaderFailure> {
    if prefix.len() < 16 {
        return Err(ReaderFailure::new(
            "format",
            "Truncated ASAR Pickle extent prefix",
        ));
    }
    let read = |o: usize| {
        u32::from_le_bytes([prefix[o], prefix[o + 1], prefix[o + 2], prefix[o + 3]]) as u64
    };
    let header_bytes = read(4);
    let payload_bytes = read(8);
    let json_bytes = read(12);
    if read(0) != 4
        || header_bytes < 8
        || payload_bytes != header_bytes.wrapping_sub(4)
        || json_bytes > payload_bytes.wrapping_sub(4)
    {
        return Err(ReaderFailure::new(
            "format",
            "ASAR header has invalid Pickle extents",
        ));
    }
    if let Some(archive_bytes) = archive_bytes
        && (archive_bytes < 8 || header_bytes > archive_bytes - 8)
    {
        return Err(ReaderFailure::new(
            "format",
            "ASAR header leaves its observed container",
        ));
    }
    Ok(Extents {
        header_bytes,
        json_bytes,
    })
}

fn is_json_ws(value: u8) -> bool {
    value == 0x20 || value == 0x09 || value == 0x0a || value == 0x0d
}

/// Finalized ASAR signature probe over the retained prefix.
pub fn asar_header_matches(prefix: &[u8], archive_bytes: u64) -> AsarProbe {
    let extents = match parse_extents(prefix, Some(archive_bytes)) {
        Ok(extents) => extents,
        Err(_) => return AsarProbe::Rejected,
    };
    if extents.json_bytes == 0 {
        return AsarProbe::Rejected;
    }
    if extents.header_bytes > MAX_ASAR_HEADER_BYTES {
        return AsarProbe::Limit;
    }
    let json_start = 16usize;
    let mut scanned: u64 = 0;
    while scanned < extents.json_bytes {
        if 16 + scanned >= MAX_ASAR_HEADER_PROBE_BYTES {
            return AsarProbe::Limit;
        }
        let index = json_start + scanned as usize;
        if index >= prefix.len() {
            return AsarProbe::Limit;
        }
        let value = prefix[index];
        if !is_json_ws(value) {
            return if value == 0x7b {
                AsarProbe::Matched
            } else {
                AsarProbe::Rejected
            };
        }
        scanned += 1;
    }
    AsarProbe::Rejected
}

/// One expanded header-tree entry.
struct ListedEntry {
    path: String,
    kind: &'static str,
    declared_size: Option<u64>,
    executable: bool,
    declared_sha256: Option<String>,
    unpacked: bool,
    offset: Option<u64>,
}

fn node_integrity_sha256(node: &Value) -> Option<String> {
    let integrity = node.get("integrity")?;
    if integrity.get("algorithm").and_then(Value::as_str) != Some("SHA256") {
        return None;
    }
    let hash = integrity.get("hash").and_then(Value::as_str)?;
    if hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Some(hash.to_owned())
    } else {
        None
    }
}

/// `readAsarListing`: depth-first expansion with path-component admission and a
/// bounded representation budget. Returns entries sorted by logical path.
fn read_listing(
    header: &Value,
    cancellation: &Cancellation,
) -> Result<Vec<ListedEntry>, ReaderFailure> {
    let root_files = header
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| ReaderFailure::new("format", "ASAR root has no files table"))?;
    // Frames own their `(name, node)` pairs so subtrees can be pushed without
    // borrowing the parent map.
    struct Frame {
        parent: String,
        children: Vec<(String, Value)>,
        index: usize,
    }
    let ordered_children = |map: &serde_json::Map<String, Value>| -> Vec<(String, Value)> {
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    };
    let mut entries: Vec<ListedEntry> = Vec::new();
    let mut pending = vec![Frame {
        parent: String::new(),
        children: ordered_children(root_files),
        index: 0,
    }];
    let mut retained_bytes: u64 = 0;
    let mut examined: u64 = 0;
    while let Some(frame) = pending.last_mut() {
        if examined % 128 == 0 && cancellation.reason().is_some() {
            return Err(ReaderFailure::new("cancelled", "ASAR operation cancelled"));
        }
        examined += 1;
        if frame.index >= frame.children.len() {
            pending.pop();
            continue;
        }
        let (name, raw) = frame.children[frame.index].clone();
        let parent = frame.parent.clone();
        frame.index += 1;
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\0')
        {
            return Err(ReaderFailure::new(
                "path",
                "ASAR header has an unsafe path component",
            ));
        }
        let units =
            parent.chars().count() + name.chars().count() + if parent.is_empty() { 0 } else { 1 };
        retained_bytes += units as u64 * 2 + 256;
        if retained_bytes > MAX_LISTING_BYTES {
            return Err(ReaderFailure::new(
                "limit",
                "ASAR expanded listing exceeds its 64 MiB representation budget",
            ));
        }
        let path = if parent.is_empty() {
            name.clone()
        } else {
            format!("{parent}/{name}")
        };
        let files = raw.get("files").and_then(Value::as_object).cloned();
        let link = raw.get("link").and_then(Value::as_str);
        let size = raw.get("size").and_then(Value::as_u64);
        if files.is_none() && link.is_none() && size.is_none() {
            return Err(ReaderFailure::new(
                "format",
                "ASAR entry has no directory, link or file metadata",
            ));
        }
        let kind = if files.is_some() {
            "directory"
        } else if link.is_some() {
            "symlink"
        } else {
            "file"
        };
        entries.push(ListedEntry {
            path: path.clone(),
            kind,
            declared_size: size,
            executable: raw.get("executable").and_then(Value::as_bool) == Some(true),
            declared_sha256: node_integrity_sha256(&raw),
            unpacked: raw.get("unpacked").and_then(Value::as_bool) == Some(true),
            offset: raw
                .get("offset")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<u64>().ok()),
        });
        if let Some(files) = files {
            pending.push(Frame {
                parent: path,
                children: ordered_children(&files),
                index: 0,
            });
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

/// ASAR reader over an in-memory capture of the whole container.
pub struct AsarArtifactReader {
    bytes: Vec<u8>,
    header_bytes: u64,
    listing: Vec<ListedEntry>,
    prepared: bool,
}

impl AsarArtifactReader {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            header_bytes: 0,
            listing: Vec::new(),
            prepared: false,
        }
    }

    fn prepare(&mut self, cancellation: &Cancellation) -> Result<(), ReaderFailure> {
        if self.prepared {
            return Ok(());
        }
        let archive_bytes = self.bytes.len() as u64;
        if self.bytes.len() < 16 {
            return Err(ReaderFailure::new("format", "Truncated ASAR size pickle"));
        }
        let extents = parse_extents(&self.bytes[..16], Some(archive_bytes))?;
        if extents.header_bytes > MAX_ASAR_HEADER_BYTES {
            return Err(ReaderFailure::new(
                "limit",
                format!("ASAR header exceeds the {MAX_ASAR_HEADER_BYTES} byte decode budget"),
            ));
        }
        self.header_bytes = extents.header_bytes;
        let json_start = 16usize;
        let json_end = json_start + extents.json_bytes as usize;
        if json_end > self.bytes.len() {
            return Err(ReaderFailure::new("format", "ASAR header is truncated"));
        }
        let header: Value =
            serde_json::from_slice(&self.bytes[json_start..json_end]).map_err(|error| {
                ReaderFailure::new("format", format!("ASAR header is not valid JSON: {error}"))
            })?;
        self.listing = read_listing(&header, cancellation)?;
        self.prepared = true;
        Ok(())
    }
}

impl ArtifactReader for AsarArtifactReader {
    fn format(&self) -> &'static str {
        "asar"
    }

    fn entries(
        &mut self,
        cancellation: &Cancellation,
        _omissions: &mut Vec<ArtifactTraversalOmission>,
    ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
        self.prepare(cancellation)?;
        let mut out = Vec::with_capacity(self.listing.len());
        for listed in &self.listing {
            out.push(ArtifactEntry {
                path: listed.path.clone(),
                kind: listed.kind,
                declared_size: if listed.kind == "directory" {
                    None
                } else {
                    listed.declared_size
                },
                compressed_size: None,
                executable: listed.executable,
                encrypted: false,
                byte_offset: None,
                declared_sha256: listed.declared_sha256.clone(),
                unpacked: listed.unpacked,
                limitations: if listed.kind == "symlink" {
                    vec!["ASAR symlink target was not followed or disclosed.".to_owned()]
                } else {
                    Vec::new()
                },
                adapter_key: listed.path.clone(),
            });
        }
        Ok(out)
    }

    fn open(
        &mut self,
        entry: &ArtifactEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, ReaderFailure> {
        self.prepare(cancellation)?;
        let listed = self
            .listing
            .iter()
            .find(|listed| listed.path == entry.adapter_key && listed.kind == "file")
            .ok_or_else(|| {
                ReaderFailure::new(
                    "integrity",
                    format!("ASAR entry was not produced by this reader: {}", entry.path),
                )
            })?;
        if listed.unpacked {
            return Err(ReaderFailure::new(
                "unavailable",
                format!(
                    "ASAR unpacked companion bytes are unavailable for {}",
                    entry.path
                ),
            ));
        }
        let size = listed.declared_size.unwrap_or(0);
        let offset = listed.offset.ok_or_else(|| {
            ReaderFailure::new(
                "format",
                format!("ASAR entry range is outside its container: {}", entry.path),
            )
        })?;
        let start = 8u64 + self.header_bytes + offset;
        let archive = self.bytes.len() as u64;
        if start > archive || size > archive - start {
            return Err(ReaderFailure::new(
                "format",
                format!("ASAR entry range is outside its container: {}", entry.path),
            ));
        }
        Ok(self.bytes[start as usize..(start + size) as usize].to_vec())
    }

    fn close(&mut self) -> Result<(), ReaderFailure> {
        self.bytes = Vec::new();
        self.listing = Vec::new();
        Ok(())
    }
}
