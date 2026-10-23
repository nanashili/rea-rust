//! Bounded, read-only inventory of a PE resource directory.
//!
//! The resource tree owns PE-specific interpretation. Its report preserves
//! original file ranges and identities; icon relationships remain static
//! resource-table facts rather than claims about runtime loading.

use crate::{PeFormat, ResourceLayout, read_resource_layout};
use rea_core::cancellation::Cancellation;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt, io,
};

pub const MAX_FILE_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_DIRECTORY_ENTRIES: usize = 65_536;
pub const DEFAULT_FILE_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_DIRECTORY_ENTRIES: usize = 16_384;
const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct Input {
    pub max_file_bytes: usize,
    pub max_entries: usize,
}

#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    Unsupported(&'static str),
    ResourceLimit {
        boundary: &'static str,
        maximum: usize,
        reason: &'static str,
    },
    Cancelled(String),
    Encoding(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) | Self::Unsupported(reason) => formatter.write_str(reason),
            Self::ResourceLimit { reason, .. } => formatter.write_str(reason),
            Self::Cancelled(reason) => write!(formatter, "cancelled: {reason}"),
            Self::Encoding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct Range {
    pub offset: usize,
    pub bytes: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Identity {
    Id {
        id: u32,
    },
    Name {
        name: String,
        utf16le_hex: String,
        location: Range,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Directory {
    pub location: Range,
    pub characteristics: u32,
    pub timestamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub named_entries: u16,
    pub id_entries: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct Payload {
    pub rva: u32,
    pub location: Range,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Resource {
    pub index: usize,
    pub r#type: Identity,
    pub name: Identity,
    pub language: Identity,
    pub entry_locations: Vec<Range>,
    pub data_entry_location: Range,
    pub code_page: u32,
    pub reserved: u32,
    pub payload: Payload,
}

#[derive(Clone, Debug, Serialize)]
pub struct IconImage {
    pub location: Range,
    pub width: u8,
    pub height: u8,
    pub color_count: u8,
    pub reserved: u8,
    pub planes: u16,
    pub bit_count: u16,
    pub declared_bytes: u32,
    pub resource_id: u16,
    pub candidate_resource_indices: Vec<usize>,
    pub language_candidate_resource_indices: Vec<usize>,
    pub reference: IconReference,
    pub same_language_resource_index: Option<usize>,
    pub resolved_location: Option<Range>,
    pub size_matches: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IconReference {
    Missing,
    NoLanguageMatch,
    Ambiguous,
    Resolved,
}

#[derive(Clone, Debug, Serialize)]
pub struct CursorImage {
    pub location: Range,
    pub width: u8,
    pub height: u8,
    pub color_count: u8,
    pub reserved: u8,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    pub declared_bytes: u32,
    pub resource_id: u16,
    pub candidate_resource_indices: Vec<usize>,
    pub same_language_resource_index: Option<usize>,
    pub resolved_location: Option<Range>,
    pub reference: IconReference,
    pub size_matches: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IconGroup {
    pub resource_index: usize,
    pub images: Vec<IconImage>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IconResource {
    pub resource_index: usize,
    pub resource_id: Identity,
    pub location: Range,
    pub raw_bytes: Vec<u8>,
    pub format: &'static str,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub bit_count: Option<u16>,
    pub malformed: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CursorResource {
    pub resource_index: usize,
    pub resource_id: Identity,
    pub location: Range,
    pub raw_bytes: Vec<u8>,
    pub format: &'static str,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub bit_count: Option<u16>,
    pub hotspot_x: Option<u16>,
    pub hotspot_y: Option<u16>,
    pub malformed: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CursorGroup {
    pub resource_index: usize,
    pub images: Vec<CursorImage>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BitmapResource {
    pub resource_index: usize,
    pub layout: &'static str,
    pub location: Range,
    pub header_location: Range,
    pub width: i32,
    pub height: i32,
    pub planes: u16,
    pub bit_count: u16,
    pub compression: u32,
    pub declared_image_bytes: u32,
    pub declared_file_bytes: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FontResource {
    pub resource_index: usize,
    pub kind: &'static str,
    pub location: Range,
    pub header_location: Range,
    pub declared_bytes: usize,
    pub declared_entry_count: Option<u16>,
    pub font_id: Identity,
    pub font_name: Option<Identity>,
    pub associated_resource_ids: Vec<u16>,
    pub entry_locations: Vec<Range>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VersionInfo {
    pub location: Range,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub strings: BTreeMap<String, String>,
    pub string_locations: BTreeMap<String, Range>,
    pub translations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ManifestResource {
    pub resource_index: usize,
    pub r#type: Identity,
    pub name: Identity,
    pub language: Identity,
    pub code_page: u32,
    pub location: Range,
    pub raw_xml: Vec<u8>,
    pub encoding: &'static str,
    pub text: Option<String>,
    pub decode_issue: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HtmlResource {
    pub resource_index: usize,
    pub r#type: Identity,
    pub name: Identity,
    pub language: Identity,
    pub code_page: u32,
    pub location: Range,
    pub raw_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RcDataResource {
    pub resource_index: usize,
    pub r#type: Identity,
    pub name: Identity,
    pub language: Identity,
    pub code_page: u32,
    pub location: Range,
    pub raw_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StringResource {
    pub resource_index: usize,
    pub string_id: u32,
    pub name: Identity,
    pub language: Identity,
    pub code_page: u32,
    pub location: Range,
    pub value_location: Range,
    pub raw_utf16le: Vec<u8>,
    pub value: String,
    pub declared_units: u16,
    pub complete: bool,
    pub decode_issue: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DialogValue {
    None,
    Ordinal { value: u16 },
    Text { value: String, location: Range },
}

#[derive(Clone, Debug, Serialize)]
pub struct DialogControl {
    pub location: Range,
    pub style: u32,
    pub ex_style: u32,
    pub x: i16,
    pub y: i16,
    pub width: i16,
    pub height: i16,
    pub identifier: u32,
    pub class: DialogValue,
    pub title: DialogValue,
    pub creation_data_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct DialogResource {
    pub resource_index: usize,
    pub kind: &'static str,
    pub location: Range,
    pub style: u32,
    pub ex_style: u32,
    pub x: i16,
    pub y: i16,
    pub width: i16,
    pub height: i16,
    pub menu: DialogValue,
    pub class: DialogValue,
    pub title: DialogValue,
    pub controls: Vec<DialogControl>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MenuItem {
    pub location: Range,
    pub flags: u32,
    pub identifier: Option<u32>,
    pub text: DialogValue,
    pub depth: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct MenuResource {
    pub resource_index: usize,
    pub kind: &'static str,
    pub location: Range,
    pub items: Vec<MenuItem>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AcceleratorEntry {
    pub location: Range,
    pub flags: u16,
    pub key: u16,
    pub command: u16,
    pub is_last: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AcceleratorResource {
    pub resource_index: usize,
    pub location: Range,
    pub entries: Vec<AcceleratorEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DirectoryRange {
    pub rva: u32,
    pub location: Range,
    pub data_directory_location: Range,
}

#[derive(Clone, Debug, Serialize)]
pub struct Coverage {
    pub status: &'static str,
    pub examined_entries: usize,
    pub resources: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub artifact: Artifact,
    pub format: &'static str,
    pub machine: u32,
    pub directory: Option<DirectoryRange>,
    pub directories: Vec<Directory>,
    pub resources: Vec<Resource>,
    pub icon_groups: Vec<IconGroup>,
    pub icons: Vec<IconResource>,
    pub cursors: Vec<CursorResource>,
    pub cursor_groups: Vec<CursorGroup>,
    pub bitmaps: Vec<BitmapResource>,
    pub fonts: Vec<FontResource>,
    pub version_info: Option<VersionInfo>,
    pub manifests: Vec<ManifestResource>,
    pub html: Vec<HtmlResource>,
    pub rcdata: Vec<RcDataResource>,
    pub strings: Vec<StringResource>,
    pub dialogs: Vec<DialogResource>,
    pub menus: Vec<MenuResource>,
    pub accelerators: Vec<AcceleratorResource>,
    pub coverage: Coverage,
    pub limitations: Vec<String>,
}

#[derive(Clone)]
struct OccupiedRange {
    range: Range,
    kind: RangeKind,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RangeKind {
    Directory,
    Name,
    DataEntry,
    Payload,
}

struct Parser<'a> {
    bytes: &'a [u8],
    layout: ResourceLayout,
    root: usize,
    input: Input,
    cancellation: &'a Cancellation,
    directories: Vec<Directory>,
    resources: Vec<Resource>,
    occupied: Vec<OccupiedRange>,
    names: HashMap<usize, Identity>,
    examined_entries: usize,
    metadata_bytes: usize,
}

impl Parser<'_> {
    fn check_active(&self) -> Result<(), Error> {
        match self.cancellation.reason() {
            Some(reason) => Err(Error::Cancelled(reason.to_owned())),
            None => Ok(()),
        }
    }

    fn ensure_capacity(&self, additional: usize) -> Result<(), Error> {
        if additional > MAX_METADATA_BYTES.saturating_sub(self.metadata_bytes) {
            return Err(Error::ResourceLimit {
                boundary: "memory",
                maximum: MAX_METADATA_BYTES,
                reason: "PE resource metadata exceeds the 8 MiB complete-result allocation budget.",
            });
        }
        Ok(())
    }

    fn account<T: Serialize>(&mut self, value: &T) -> Result<(), Error> {
        let remaining = MAX_METADATA_BYTES
            .saturating_sub(self.metadata_bytes)
            .saturating_sub(1);
        let length = serialized_length(value, remaining)?;
        let projected = length.saturating_add(1);
        self.ensure_capacity(projected)?;
        self.metadata_bytes += projected;
        Ok(())
    }

    fn reserve_name(&self, utf16_units: usize) -> Result<(), Error> {
        let projected = utf16_units
            .checked_mul(10)
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or(Error::ResourceLimit {
                boundary: "memory",
                maximum: MAX_METADATA_BYTES,
                reason: "PE resource metadata exceeds the 8 MiB complete-result allocation budget.",
            })?;
        self.ensure_capacity(projected)
    }

    fn relative(&self, at: usize, length: usize) -> Result<usize, Error> {
        let directory_size = self.layout.directory_size as usize;
        let end = at
            .checked_add(length)
            .ok_or(Error::Malformed("resource directory offset overflows"))?;
        if end > directory_size {
            return Err(Error::Malformed(
                "resource directory offset leaves the declared resource interval",
            ));
        }
        let absolute = self
            .root
            .checked_add(at)
            .ok_or(Error::Malformed("resource file offset overflows"))?;
        checked_range(self.bytes, absolute, length)?;
        Ok(absolute)
    }

    fn record_range(&mut self, offset: usize, size: usize, kind: RangeKind) -> Range {
        let range = Range {
            offset,
            bytes: size,
        };
        if size > 0 {
            self.occupied.push(OccupiedRange {
                range: range.clone(),
                kind,
            });
        }
        range
    }

    fn read_identity(&mut self, encoded: u32) -> Result<Identity, Error> {
        if encoded & 0x8000_0000 == 0 {
            return Ok(Identity::Id { id: encoded });
        }

        let relative_at = (encoded & 0x7fff_ffff) as usize;
        if let Some(identity) = self.names.get(&relative_at) {
            return Ok(identity.clone());
        }
        if !relative_at.is_multiple_of(2) {
            return Err(Error::Malformed("unaligned PE resource name"));
        }

        let start = self.relative(relative_at, 2)?;
        let utf16_units = usize::from(read_u16(self.bytes, start)?);
        self.reserve_name(utf16_units)?;
        let byte_length = utf16_units
            .checked_mul(2)
            .ok_or(Error::Malformed("PE resource name length overflows"))?;
        self.relative(relative_at, 2 + byte_length)?;
        let raw = &self.bytes[start + 2..start + 2 + byte_length];
        let units = raw
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect::<Vec<_>>();
        let identity = Identity::Name {
            name: String::from_utf16_lossy(&units),
            utf16le_hex: lowercase_hex(raw),
            location: self.record_range(start, 2 + byte_length, RangeKind::Name),
        };
        self.names.insert(relative_at, identity.clone());
        Ok(identity)
    }

    fn visit(
        &mut self,
        at: usize,
        path: &[Identity],
        entry_locations: &[Range],
        ancestors: &[usize],
    ) -> Result<(), Error> {
        if ancestors.contains(&at) {
            return Err(Error::Malformed("cyclic PE resource directory"));
        }
        if !at.is_multiple_of(4) {
            return Err(Error::Malformed("unaligned PE resource directory"));
        }

        let header = self.relative(at, 16)?;
        let named = usize::from(read_u16(self.bytes, header + 12)?);
        let ids = usize::from(read_u16(self.bytes, header + 14)?);
        let count = named + ids;
        if count > self.input.max_entries.saturating_sub(self.examined_entries) {
            return Err(Error::ResourceLimit {
                boundary: "capacity",
                maximum: self.input.max_entries,
                reason: "PE resource directory entry budget exceeded; no partial inventory was returned.",
            });
        }
        self.examined_entries += count;
        let table_bytes = count
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(16))
            .ok_or(Error::Malformed("PE resource directory size overflows"))?;
        self.relative(at, table_bytes)?;

        let directory = Directory {
            location: self.record_range(header, table_bytes, RangeKind::Directory),
            characteristics: read_u32(self.bytes, header)?,
            timestamp: read_u32(self.bytes, header + 4)?,
            major_version: read_u16(self.bytes, header + 8)?,
            minor_version: read_u16(self.bytes, header + 10)?,
            named_entries: named as u16,
            id_entries: ids as u16,
        };
        self.account(&directory)?;
        self.directories.push(directory);

        let mut keys = HashSet::with_capacity(count);
        let mut nested = ancestors.to_vec();
        nested.push(at);
        for index in 0..count {
            if index % 128 == 0 {
                self.check_active()?;
            }

            let entry = header + 16 + index * 8;
            let encoded_identity = read_u32(self.bytes, entry)?;
            if ((encoded_identity & 0x8000_0000) != 0) != (index < named) {
                return Err(Error::Malformed(
                    "resource name/ID entry counts disagree with encoded identities",
                ));
            }
            let identity = self.read_identity(encoded_identity)?;
            if !keys.insert(identity_key(&identity)) {
                return Err(Error::Malformed(
                    "duplicate identity within a resource directory",
                ));
            }

            let mut next_path = path.to_vec();
            next_path.push(identity);
            let mut next_locations = entry_locations.to_vec();
            next_locations.push(Range {
                offset: entry,
                bytes: 8,
            });
            let target = read_u32(self.bytes, entry + 4)?;
            let offset = (target & 0x7fff_ffff) as usize;
            if target & 0x8000_0000 != 0 {
                if next_path.len() >= 3 {
                    return Err(Error::Malformed(
                        "unsupported resource tree deeper than type/name/language",
                    ));
                }
                self.visit(offset, &next_path, &next_locations, &nested)?;
            } else {
                self.read_resource_leaf(offset, &next_path, &next_locations)?;
            }
        }
        Ok(())
    }

    fn read_resource_leaf(
        &mut self,
        offset: usize,
        path: &[Identity],
        entry_locations: &[Range],
    ) -> Result<(), Error> {
        if path.len() != 3 {
            return Err(Error::Malformed(
                "unsupported resource leaf outside the type/name/language profile",
            ));
        }
        let data = self.relative(offset, 16)?;
        if !offset.is_multiple_of(4) {
            return Err(Error::Malformed("unaligned resource data entry"));
        }

        let rva = read_u32(self.bytes, data)?;
        let size = read_u32(self.bytes, data + 4)?;
        let payload_offset = self
            .layout
            .map_rva(self.bytes, rva, size)
            .map_err(map_layout_error)?;
        let (Some(resource_type), Some(name), Some(language)) =
            (path.first(), path.get(1), path.get(2))
        else {
            return Err(Error::Malformed("incomplete resource identity"));
        };

        let resource = Resource {
            index: self.resources.len(),
            r#type: resource_type.clone(),
            name: name.clone(),
            language: language.clone(),
            entry_locations: entry_locations.to_vec(),
            data_entry_location: self.record_range(data, 16, RangeKind::DataEntry),
            code_page: read_u32(self.bytes, data + 8)?,
            reserved: read_u32(self.bytes, data + 12)?,
            payload: Payload {
                rva,
                location: self.record_range(payload_offset, size as usize, RangeKind::Payload),
                sha256: String::new(),
            },
        };
        self.account(&resource)?;
        self.resources.push(resource);
        Ok(())
    }
}

/// Decode the conventional type/name/language tree without executing the image.
pub fn read(
    bytes: &[u8],
    artifact: Artifact,
    input: Input,
    cancellation: &Cancellation,
) -> Result<Report, Error> {
    check_cancellation(cancellation)?;
    let layout = read_resource_layout(bytes).map_err(map_layout_error)?;
    let root = if layout.directory_size == 0 {
        0
    } else {
        layout
            .map_rva(bytes, layout.directory_rva, layout.directory_size)
            .map_err(map_layout_error)?
    };
    let mut parser = Parser {
        bytes,
        layout,
        root,
        input,
        cancellation,
        directories: Vec::new(),
        resources: Vec::new(),
        occupied: Vec::new(),
        names: HashMap::new(),
        examined_entries: 0,
        metadata_bytes: 0,
    };

    if parser.layout.directory_size > 0 {
        parser.visit(0, &[], &[], &[])?;
    }
    reject_overlapping_ranges(&mut parser.occupied)?;
    hash_payloads(&mut parser)?;
    let icon_groups = read_icon_groups(&mut parser)?;
    let (icons, icon_issues) = read_icons(&parser);
    let (cursors, cursor_issues) = read_cursors(&parser);
    let cursor_groups = read_cursor_groups(&mut parser)?;
    let (bitmaps, bitmap_issues) = read_bitmaps(&parser);
    let (fonts, font_issues) = read_fonts(&parser);
    let (version_info, version_issues) = read_version_info(&parser);
    let (manifests, manifest_issues) = read_manifests(&parser);
    let (html, html_issues) = read_html(&parser);
    let (rcdata, rcdata_issues) = read_rcdata(&parser);
    let (strings, string_issues) = read_strings(&parser);
    let (dialogs, dialog_issues) = read_dialogs(&parser);
    let (menus, menu_issues) = read_menus(&parser);
    let (accelerators, accelerator_issues) = read_accelerators(&parser);
    let mut issues = version_issues;
    issues.extend(manifest_issues);
    issues.extend(html_issues);
    issues.extend(rcdata_issues);
    issues.extend(string_issues);
    issues.extend(dialog_issues);
    issues.extend(menu_issues);
    issues.extend(accelerator_issues);
    issues.extend(icon_issues);
    issues.extend(cursor_issues);
    issues.extend(bitmap_issues);
    issues.extend(font_issues);
    let report = build_report(
        artifact,
        parser,
        icon_groups,
        icons,
        cursors,
        cursor_groups,
        bitmaps,
        fonts,
        version_info,
        manifests,
        html,
        rcdata,
        strings,
        dialogs,
        menus,
        accelerators,
        issues,
    );
    check_cancellation(cancellation)?;
    serialized_length(&report, MAX_METADATA_BYTES)?;
    Ok(report)
}

fn build_report(
    artifact: Artifact,
    parser: Parser<'_>,
    icon_groups: Vec<IconGroup>,
    icons: Vec<IconResource>,
    cursors: Vec<CursorResource>,
    cursor_groups: Vec<CursorGroup>,
    bitmaps: Vec<BitmapResource>,
    fonts: Vec<FontResource>,
    version_info: Option<VersionInfo>,
    manifests: Vec<ManifestResource>,
    html: Vec<HtmlResource>,
    rcdata: Vec<RcDataResource>,
    strings: Vec<StringResource>,
    dialogs: Vec<DialogResource>,
    menus: Vec<MenuResource>,
    accelerators: Vec<AcceleratorResource>,
    issues: Vec<String>,
) -> Report {
    let resource_count = parser.resources.len();
    let directory = (parser.layout.directory_size > 0).then_some(DirectoryRange {
        rva: parser.layout.directory_rva,
        location: Range {
            offset: parser.root,
            bytes: parser.layout.directory_size as usize,
        },
        data_directory_location: Range {
            offset: parser.layout.directory_at,
            bytes: 8,
        },
    });
    Report {
        artifact,
        format: match parser.layout.format {
            PeFormat::Pe32 => "pe32",
            PeFormat::Pe32Plus => "pe32-plus",
        },
        machine: parser.layout.machine,
        directory,
        directories: parser.directories,
        resources: parser.resources,
        icon_groups,
        icons,
        cursors,
        cursor_groups,
        bitmaps,
        fonts,
        version_info,
        manifests,
        html,
        rcdata,
        strings,
        dialogs,
        menus,
        accelerators,
        coverage: Coverage {
            status: "complete",
            examined_entries: parser.examined_entries,
            resources: resource_count,
        },
        limitations: [
            "Static PE32/PE32+ type/name/language resource inventory; RT_MANIFEST bytes are retained up to 1 MiB without parsing or executing XML, while other payloads remain opaque.".into(),
            "Icon candidates are resource-table relationships. Language fallback, image decoding and actual shell/window loading are not observed.".into(),
            "Exact shared byte ranges are retained; non-identical overlapping resource structures or payloads are rejected.".into(),
        ].into_iter().chain(issues).collect(),
    }
}

fn hash_payloads(parser: &mut Parser<'_>) -> Result<(), Error> {
    let mut hashes = HashMap::<(usize, usize), String>::new();
    for index in 0..parser.resources.len() {
        let range = &parser.resources[index].payload.location;
        let key = (range.offset, range.bytes);
        let digest = if let Some(digest) = hashes.get(&key) {
            digest.clone()
        } else {
            let digest = hash_range(parser.bytes, range, parser.cancellation)?;
            hashes.insert(key, digest.clone());
            digest
        };
        parser.resources[index].payload.sha256 = digest;
    }
    Ok(())
}

fn read_manifests(parser: &Parser<'_>) -> (Vec<ManifestResource>, Vec<String>) {
    let mut manifests = Vec::new();
    let mut issues = Vec::new();

    for resource in &parser.resources {
        if !matches!(&resource.r#type, Identity::Id { id: 24 }) {
            continue;
        }

        let range = &resource.payload.location;
        let end = range.offset.saturating_add(range.bytes);
        let Some(raw_xml) = parser.bytes.get(range.offset..end) else {
            issues.push(format!(
                "RT_MANIFEST resource {} is truncated; raw XML remains unavailable.",
                resource.index
            ));
            continue;
        };

        if raw_xml.is_empty() {
            issues.push(format!(
                "RT_MANIFEST resource {} has an empty payload; raw XML remains unavailable.",
                resource.index
            ));
            continue;
        }

        if raw_xml.len() > MAX_MANIFEST_BYTES {
            issues.push(format!(
                "RT_MANIFEST resource {} exceeds the 1 MiB raw XML extraction bound; raw XML remains unavailable.",
                resource.index
            ));
            continue;
        }

        let (encoding, text, decode_issue) = decode_manifest_text(raw_xml);
        if let Some(reason) = &decode_issue {
            issues.push(format!(
                "RT_MANIFEST resource {} has undecodable text: {reason}; raw bytes were retained.",
                resource.index
            ));
        }

        manifests.push(ManifestResource {
            resource_index: resource.index,
            r#type: resource.r#type.clone(),
            name: resource.name.clone(),
            language: resource.language.clone(),
            code_page: resource.code_page,
            location: range.clone(),
            raw_xml: raw_xml.to_vec(),
            encoding,
            text,
            decode_issue,
        });
    }

    (manifests, issues)
}

fn decode_manifest_text(raw: &[u8]) -> (&'static str, Option<String>, Option<String>) {
    if raw.starts_with(&[0xff, 0xfe]) {
        if (raw.len() - 2) % 2 != 0 {
            return (
                "utf16le",
                None,
                Some("truncated UTF-16LE manifest code unit".into()),
            );
        }
        return decode_utf16_manifest(
            raw[2..]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
            "utf16le",
        );
    }

    if raw.starts_with(&[0xfe, 0xff]) {
        if (raw.len() - 2) % 2 != 0 {
            return (
                "utf16be",
                None,
                Some("truncated UTF-16BE manifest code unit".into()),
            );
        }
        return decode_utf16_manifest(
            raw[2..]
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]])),
            "utf16be",
        );
    }

    match std::str::from_utf8(raw) {
        Ok(text) => ("utf8", Some(text.to_owned()), None),
        Err(_) => (
            "unknown",
            None,
            Some("manifest bytes are neither valid UTF-8 nor BOM-prefixed UTF-16 text".into()),
        ),
    }
}

fn decode_utf16_manifest(
    units: impl Iterator<Item = u16>,
    encoding: &'static str,
) -> (&'static str, Option<String>, Option<String>) {
    let units = units.collect::<Vec<_>>();
    match String::from_utf16(&units) {
        Ok(text) => (encoding, Some(text), None),
        Err(_) => (encoding, None, Some("invalid UTF-16 manifest text".into())),
    }
}

fn read_html(parser: &Parser<'_>) -> (Vec<HtmlResource>, Vec<String>) {
    let mut html = Vec::new();
    let mut issues = Vec::new();
    for resource in &parser.resources {
        if !matches!(&resource.r#type, Identity::Id { id: 23 }) {
            continue;
        }
        let range = &resource.payload.location;
        let Some(raw_bytes) = parser
            .bytes
            .get(range.offset..range.offset.saturating_add(range.bytes))
        else {
            issues.push(format!(
                "RT_HTML resource {} is truncated; raw bytes remain unavailable.",
                resource.index
            ));
            continue;
        };
        let payload_end = raw_bytes
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |index| index + 1);
        let raw_bytes = &raw_bytes[..payload_end];
        if raw_bytes.is_empty() {
            issues.push(format!(
                "RT_HTML resource {} has an empty payload; raw bytes remain unavailable.",
                resource.index
            ));
            continue;
        }
        if raw_bytes.len() > MAX_MANIFEST_BYTES {
            issues.push(format!("RT_HTML resource {} exceeds the 1 MiB raw-byte bound; raw bytes remain unavailable.", resource.index));
            continue;
        }
        html.push(HtmlResource {
            resource_index: resource.index,
            r#type: resource.r#type.clone(),
            name: resource.name.clone(),
            language: resource.language.clone(),
            code_page: resource.code_page,
            location: Range {
                offset: range.offset,
                bytes: raw_bytes.len(),
            },
            raw_bytes: raw_bytes.to_vec(),
        });
    }
    (html, issues)
}

fn read_rcdata(parser: &Parser<'_>) -> (Vec<RcDataResource>, Vec<String>) {
    let mut rcdata = Vec::new();
    let mut issues = Vec::new();
    for resource in &parser.resources {
        if !matches!(&resource.r#type, Identity::Id { id: 10 }) {
            continue;
        }
        let range = &resource.payload.location;
        let Some(raw_bytes) = parser
            .bytes
            .get(range.offset..range.offset.saturating_add(range.bytes))
        else {
            issues.push(format!(
                "RT_RCDATA resource {} is truncated; raw bytes remain unavailable.",
                resource.index
            ));
            continue;
        };
        if raw_bytes.is_empty() {
            issues.push(format!(
                "RT_RCDATA resource {} has an empty payload; raw bytes remain unavailable.",
                resource.index
            ));
            continue;
        }
        if raw_bytes.len() > MAX_MANIFEST_BYTES {
            issues.push(format!("RT_RCDATA resource {} exceeds the 1 MiB raw-byte bound; raw bytes remain unavailable.", resource.index));
            continue;
        }
        rcdata.push(RcDataResource {
            resource_index: resource.index,
            r#type: resource.r#type.clone(),
            name: resource.name.clone(),
            language: resource.language.clone(),
            code_page: resource.code_page,
            location: range.clone(),
            raw_bytes: raw_bytes.to_vec(),
        });
    }
    (rcdata, issues)
}

fn read_strings(parser: &Parser<'_>) -> (Vec<StringResource>, Vec<String>) {
    let mut strings = Vec::new();
    let mut issues = Vec::new();

    for resource in &parser.resources {
        if !matches!(&resource.r#type, Identity::Id { id: 6 }) {
            continue;
        }

        let Identity::Id { id: block_id } = resource.name.clone() else {
            issues.push(format!(
                "RT_STRING resource {} has a named block identifier; string IDs remain unknown.",
                resource.index
            ));
            continue;
        };
        let Some(first_id) = block_id
            .checked_sub(1)
            .and_then(|value| value.checked_mul(16))
        else {
            issues.push(format!(
                "RT_STRING resource {} has an invalid block identifier {}; string IDs remain unknown.",
                resource.index, block_id
            ));
            continue;
        };

        let range = &resource.payload.location;
        let Some(data) = parser
            .bytes
            .get(range.offset..range.offset.saturating_add(range.bytes))
        else {
            issues.push(format!(
                "RT_STRING resource {} is truncated; decoded strings remain unavailable.",
                resource.index
            ));
            continue;
        };
        if data.len() % 2 != 0 {
            issues.push(format!(
                "RT_STRING resource {} has an odd payload length; trailing bytes remain unavailable.",
                resource.index
            ));
        }

        let mut offset = 0usize;
        for slot in 0..16u32 {
            let Some(length_bytes) = data.get(offset..offset.saturating_add(2)) else {
                if offset == data.len() {
                    let string_id = first_id.checked_add(slot).unwrap_or(first_id);
                    strings.push(StringResource {
                        resource_index: resource.index,
                        string_id,
                        name: resource.name.clone(),
                        language: resource.language.clone(),
                        code_page: resource.code_page,
                        location: Range {
                            offset: range.offset + offset,
                            bytes: 0,
                        },
                        value_location: Range {
                            offset: range.offset + offset,
                            bytes: 0,
                        },
                        raw_utf16le: Vec::new(),
                        value: String::new(),
                        declared_units: 0,
                        complete: true,
                        decode_issue: None,
                    });
                } else {
                    issues.push(format!(
                        "RT_STRING resource {} is truncated before entry {}.",
                        resource.index, slot
                    ));
                }
                break;
            };
            let length = usize::from(u16::from_le_bytes([length_bytes[0], length_bytes[1]]));
            let value_bytes = length.saturating_mul(2);
            let end = offset
                .checked_add(2)
                .and_then(|value| value.checked_add(value_bytes));
            let Some(end) = end else {
                issues.push(format!(
                    "RT_STRING resource {} entry {} length overflows; entry remains unavailable.",
                    resource.index, slot
                ));
                break;
            };
            let Some(encoded) = data.get(offset..end) else {
                let string_id = first_id.checked_add(slot).unwrap_or(first_id);
                let raw = data.get(offset..).unwrap_or_default();
                strings.push(StringResource {
                    resource_index: resource.index,
                    string_id,
                    name: resource.name.clone(),
                    language: resource.language.clone(),
                    code_page: resource.code_page,
                    location: Range {
                        offset: range.offset + offset,
                        bytes: raw.len(),
                    },
                    value_location: Range {
                        offset: range.offset + offset.saturating_add(2),
                        bytes: raw.len().saturating_sub(2),
                    },
                    raw_utf16le: raw.to_vec(),
                    value: String::new(),
                    declared_units: length as u16,
                    complete: false,
                    decode_issue: Some("truncated length-prefixed payload".to_owned()),
                });
                issues.push(format!(
                    "RT_STRING resource {} entry {} is truncated; raw available bytes were retained.",
                    resource.index, slot
                ));
                break;
            };
            let units = encoded[2..]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            let Ok(value) = String::from_utf16(&units) else {
                let string_id = first_id.checked_add(slot).unwrap_or(first_id);
                strings.push(StringResource {
                    resource_index: resource.index,
                    string_id,
                    name: resource.name.clone(),
                    language: resource.language.clone(),
                    code_page: resource.code_page,
                    location: Range {
                        offset: range.offset + offset,
                        bytes: encoded.len(),
                    },
                    value_location: Range {
                        offset: range.offset + offset + 2,
                        bytes: encoded.len().saturating_sub(2),
                    },
                    raw_utf16le: encoded.to_vec(),
                    value: String::from_utf16_lossy(&units),
                    declared_units: length as u16,
                    complete: true,
                    decode_issue: Some("invalid UTF-16".to_owned()),
                });
                issues.push(format!(
                    "RT_STRING resource {} entry {} contains invalid UTF-16; raw code units were retained.",
                    resource.index, slot
                ));
                offset = end;
                continue;
            };
            let Some(string_id) = first_id.checked_add(slot) else {
                issues.push(format!(
                    "RT_STRING resource {} entry {} has an unrepresentable string ID.",
                    resource.index, slot
                ));
                offset = end;
                continue;
            };
            strings.push(StringResource {
                resource_index: resource.index,
                string_id,
                name: resource.name.clone(),
                language: resource.language.clone(),
                code_page: resource.code_page,
                location: Range {
                    offset: range.offset + offset,
                    bytes: encoded.len(),
                },
                value_location: Range {
                    offset: range.offset + offset + 2,
                    bytes: encoded.len().saturating_sub(2),
                },
                raw_utf16le: encoded.to_vec(),
                value,
                declared_units: length as u16,
                complete: true,
                decode_issue: None,
            });
            offset = end;
        }
    }

    (strings, issues)
}

struct DialogCursor<'a> {
    bytes: &'a [u8],
    base: usize,
    offset: usize,
}

impl<'a> DialogCursor<'a> {
    fn new(bytes: &'a [u8], base: usize) -> Self {
        Self {
            bytes,
            base,
            offset: 0,
        }
    }

    fn ensure(&self, bytes: usize) -> Result<(), String> {
        self.offset
            .checked_add(bytes)
            .filter(|end| *end <= self.bytes.len())
            .map(|_| ())
            .ok_or_else(|| format!("truncated at template offset {}", self.offset))
    }

    fn u8(&mut self) -> Result<u8, String> {
        self.ensure(1)?;
        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, String> {
        self.ensure(2)?;
        let value = u16::from_le_bytes([self.bytes[self.offset], self.bytes[self.offset + 1]]);
        self.offset += 2;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, String> {
        self.ensure(4)?;
        let value = u32::from_le_bytes([
            self.bytes[self.offset],
            self.bytes[self.offset + 1],
            self.bytes[self.offset + 2],
            self.bytes[self.offset + 3],
        ]);
        self.offset += 4;
        Ok(value)
    }

    fn i16(&mut self) -> Result<i16, String> {
        Ok(self.u16()? as i16)
    }

    fn align_dword(&mut self) -> Result<(), String> {
        let aligned = self
            .offset
            .checked_add(3)
            .map(|offset| offset & !3)
            .ok_or_else(|| "dialog alignment overflow".to_owned())?;
        if aligned > self.bytes.len() {
            return Err(format!(
                "truncated while aligning at template offset {}",
                self.offset
            ));
        }
        self.offset = aligned;
        Ok(())
    }

    fn value(&mut self) -> Result<DialogValue, String> {
        let start = self.offset;
        let first = self.u16()?;
        match first {
            0 => Ok(DialogValue::None),
            0xffff => Ok(DialogValue::Ordinal { value: self.u16()? }),
            first => {
                let mut units = vec![first];
                loop {
                    let unit = self.u16()?;
                    if unit == 0 {
                        break;
                    }
                    units.push(unit);
                }
                let value = String::from_utf16(&units)
                    .map_err(|_| format!("invalid UTF-16 at template offset {start}"))?;
                Ok(DialogValue::Text {
                    value,
                    location: Range {
                        offset: self.base + start,
                        bytes: self.offset - start,
                    },
                })
            }
        }
    }

    fn creation_data_bytes(&mut self) -> Result<usize, String> {
        let bytes = usize::from(self.u16()?);
        self.ensure(bytes)?;
        self.offset += bytes;
        Ok(bytes)
    }
}

fn read_dialogs(parser: &Parser<'_>) -> (Vec<DialogResource>, Vec<String>) {
    let mut dialogs = Vec::new();
    let mut issues = Vec::new();

    for resource in &parser.resources {
        if !matches!(&resource.r#type, Identity::Id { id: 5 }) {
            continue;
        }
        let range = &resource.payload.location;
        let Some(data) = parser
            .bytes
            .get(range.offset..range.offset.saturating_add(range.bytes))
        else {
            issues.push(format!(
                "RT_DIALOG resource {} is truncated; dialog remains unavailable.",
                resource.index
            ));
            continue;
        };
        let extended = data.len() >= 4
            && u16::from_le_bytes([data[0], data[1]]) == 1
            && u16::from_le_bytes([data[2], data[3]]) == 0xffff;
        let kind = if extended { "dialogex" } else { "dialog" };
        match parse_dialog(
            data,
            range.offset,
            kind,
            extended,
            resource.index,
            range.clone(),
        ) {
            Ok(dialog) => dialogs.push(dialog),
            Err(reason) => issues.push(format!(
                "RT_{} resource {} is malformed: {reason}; dialog remains unavailable.",
                kind.to_uppercase(),
                resource.index
            )),
        }
    }

    (dialogs, issues)
}

fn parse_dialog(
    data: &[u8],
    base: usize,
    kind: &'static str,
    extended: bool,
    resource_index: usize,
    location: Range,
) -> Result<DialogResource, String> {
    let mut cursor = DialogCursor::new(data, base);
    if extended {
        if cursor.u16()? != 1 || cursor.u16()? != 0xffff {
            return Err("invalid DIALOGEX version or signature".to_owned());
        }
        let _help_id = cursor.u32()?;
    }
    let (ex_style, style) = if extended {
        (cursor.u32()?, cursor.u32()?)
    } else {
        let style = cursor.u32()?;
        let ex_style = cursor.u32()?;
        (ex_style, style)
    };
    let control_count = usize::from(cursor.u16()?);
    let x = cursor.i16()?;
    let y = cursor.i16()?;
    let width = cursor.i16()?;
    let height = cursor.i16()?;
    let menu = cursor.value()?;
    let class = cursor.value()?;
    let title = cursor.value()?;
    if style & 0x40 != 0 {
        let _point_size = cursor.u16()?;
        if extended {
            let _weight = cursor.u16()?;
            let _italic = cursor.u8()?;
            let _charset = cursor.u8()?;
        }
        let _font = cursor.value()?;
    }

    let mut controls = Vec::with_capacity(control_count);
    for _ in 0..control_count {
        cursor.align_dword()?;
        let start = cursor.offset;
        if extended {
            let _help_id = cursor.u32()?;
        }
        let ex_style = cursor.u32()?;
        let style = cursor.u32()?;
        let x = cursor.i16()?;
        let y = cursor.i16()?;
        let width = cursor.i16()?;
        let height = cursor.i16()?;
        let identifier = if extended {
            cursor.u32()?
        } else {
            u32::from(cursor.u16()?)
        };
        let class = cursor.value()?;
        let title = cursor.value()?;
        let creation_data_bytes = cursor.creation_data_bytes()?;
        controls.push(DialogControl {
            location: Range {
                offset: base + start,
                bytes: cursor.offset - start,
            },
            style,
            ex_style,
            x,
            y,
            width,
            height,
            identifier,
            class,
            title,
            creation_data_bytes,
        });
    }

    Ok(DialogResource {
        resource_index,
        kind,
        location,
        style,
        ex_style,
        x,
        y,
        width,
        height,
        menu,
        class,
        title,
        controls,
    })
}

fn read_menus(parser: &Parser<'_>) -> (Vec<MenuResource>, Vec<String>) {
    let mut menus = Vec::new();
    let mut issues = Vec::new();

    for resource in &parser.resources {
        if !matches!(&resource.r#type, Identity::Id { id: 4 }) {
            continue;
        }
        let range = &resource.payload.location;
        let Some(data) = parser
            .bytes
            .get(range.offset..range.offset.saturating_add(range.bytes))
        else {
            issues.push(format!(
                "RT_MENU resource {} is truncated; menu remains unavailable.",
                resource.index
            ));
            continue;
        };
        let kind = if data.len() >= 4
            && u16::from_le_bytes([data[0], data[1]]) == 1
            && u16::from_le_bytes([data[2], data[3]]) == 4
        {
            "menuex"
        } else {
            "menu"
        };
        let result = if kind == "menu" {
            parse_standard_menu(data, range.offset)
        } else {
            parse_menuex(data, range.offset)
        };
        match result {
            Ok(items) => menus.push(MenuResource {
                resource_index: resource.index,
                kind,
                location: range.clone(),
                items,
            }),
            Err(reason) => issues.push(format!(
                "RT_{} resource {} is malformed: {reason}; menu remains unavailable.",
                kind.to_uppercase(),
                resource.index
            )),
        }
    }

    (menus, issues)
}

fn parse_standard_menu(data: &[u8], base: usize) -> Result<Vec<MenuItem>, String> {
    let mut cursor = DialogCursor::new(data, base);
    if cursor.u32()? != 0 || cursor.u32()? != 4 {
        return Err("invalid MENU template header".to_owned());
    }
    let mut items = Vec::new();
    let mut depth = 0usize;
    while cursor.offset < data.len() {
        if items.len() >= 4096 {
            return Err("menu item bound exceeded".to_owned());
        }
        let start = cursor.offset;
        let flags = cursor.u32()?;
        let popup = flags & 0x10 != 0;
        let identifier = (!popup).then(|| cursor.u16()).transpose()?.map(u32::from);
        let text = cursor.value()?;
        let end = flags & 0x80 != 0;
        items.push(MenuItem {
            location: Range {
                offset: base + start,
                bytes: cursor.offset - start,
            },
            flags,
            identifier,
            text,
            depth,
        });
        if end {
            if depth == 0 {
                break;
            }
            depth -= 1;
        }
        if popup {
            depth = depth.saturating_add(1);
        }
    }
    if items.is_empty() {
        return Err("menu contains no items".to_owned());
    }
    Ok(items)
}

fn parse_menuex(data: &[u8], base: usize) -> Result<Vec<MenuItem>, String> {
    let mut cursor = DialogCursor::new(data, base);
    if cursor.u16()? != 1 || cursor.u16()? != 4 {
        return Err("invalid MENUEX template header".to_owned());
    }
    let _help_id = cursor.u32()?;
    let _ex_style = cursor.u32()?;
    let count = usize::try_from(cursor.u32()?)
        .map_err(|_| "MENUEX item count is not representable".to_owned())?;
    if count > 4096 {
        return Err("MENUEX item bound exceeded".to_owned());
    }
    let mut items = Vec::with_capacity(count);
    let mut depth = 0usize;
    for _ in 0..count {
        let start = cursor.offset;
        let flags = cursor.u32()?;
        let _state = cursor.u32()?;
        let identifier = Some(cursor.u32()?);
        let resource_info = cursor.u16()?;
        let text = cursor.value()?;
        let popup = resource_info & 1 != 0;
        if popup {
            let _help_id = cursor.u32()?;
            let _ex_style = cursor.u32()?;
            let _popup_offset = cursor.u32()?;
        }
        let end = resource_info & 0x80 != 0;
        items.push(MenuItem {
            location: Range {
                offset: base + start,
                bytes: cursor.offset - start,
            },
            flags: flags | u32::from(resource_info) << 16,
            identifier,
            text,
            depth,
        });
        if end {
            depth = depth.saturating_sub(1);
        }
        if popup {
            depth = depth.saturating_add(1);
        }
    }
    Ok(items)
}

fn read_accelerators(parser: &Parser<'_>) -> (Vec<AcceleratorResource>, Vec<String>) {
    let mut accelerators = Vec::new();
    let mut issues = Vec::new();

    for resource in &parser.resources {
        if !matches!(&resource.r#type, Identity::Id { id: 9 }) {
            continue;
        }
        let range = &resource.payload.location;
        let Some(data) = parser
            .bytes
            .get(range.offset..range.offset.saturating_add(range.bytes))
        else {
            issues.push(format!(
                "RT_ACCELERATOR resource {} is truncated; accelerator table remains unavailable.",
                resource.index
            ));
            continue;
        };
        match parse_accelerator_table(data, range.offset, resource.index, range.clone()) {
            Ok(table) => accelerators.push(table),
            Err(reason) => issues.push(format!(
                "RT_ACCELERATOR resource {} is malformed: {reason}; accelerator table remains unavailable.",
                resource.index
            )),
        }
    }

    (accelerators, issues)
}

fn parse_accelerator_table(
    data: &[u8],
    base: usize,
    resource_index: usize,
    location: Range,
) -> Result<AcceleratorResource, String> {
    if data.is_empty() || data.len() % 6 != 0 {
        return Err("payload is not a whole sequence of six-byte entries".to_owned());
    }
    let mut entries = Vec::new();
    for (index, chunk) in data.chunks_exact(6).enumerate() {
        if index >= 4096 {
            return Err("accelerator entry bound exceeded".to_owned());
        }
        let flags = u16::from_le_bytes([chunk[0], chunk[1]]);
        let key = u16::from_le_bytes([chunk[2], chunk[3]]);
        let command = u16::from_le_bytes([chunk[4], chunk[5]]);
        let is_last = flags & 0x80 != 0;
        entries.push(AcceleratorEntry {
            location: Range {
                offset: base + index * 6,
                bytes: 6,
            },
            flags,
            key,
            command,
            is_last,
        });
        if is_last {
            if (index + 1) * 6 != data.len() {
                return Err("last-entry marker appears before the payload end".to_owned());
            }
            return Ok(AcceleratorResource {
                resource_index,
                location,
                entries,
            });
        }
    }
    Err("accelerator table has no last-entry marker".to_owned())
}

const MAX_VERSION_DEPTH: usize = 32;
const MAX_VERSION_BLOCKS: usize = 4096;

fn read_version_info(parser: &Parser<'_>) -> (Option<VersionInfo>, Vec<String>) {
    let Some(resource) = parser
        .resources
        .iter()
        .find(|resource| matches!(resource.r#type, Identity::Id { id: 16 }))
    else {
        return (None, Vec::new());
    };
    let range = &resource.payload.location;
    let Some(data) = parser
        .bytes
        .get(range.offset..range.offset.saturating_add(range.bytes))
    else {
        return (
            None,
            vec!["RT_VERSION payload is truncated; version metadata remains unknown.".into()],
        );
    };
    match parse_version_payload(data, range.offset) {
        Ok(parsed) => (
            Some(VersionInfo {
                location: range.clone(),
                file_version: parsed.file_version,
                product_version: parsed.product_version,
                strings: parsed.strings,
                string_locations: parsed.string_locations,
                translations: parsed.translations,
            }),
            Vec::new(),
        ),
        Err(reason) => (
            None,
            vec![format!(
                "RT_VERSION payload is malformed: {reason}; version metadata remains unknown."
            )],
        ),
    }
}

fn format_version(high: u32, low: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        high >> 16,
        high & 0xffff,
        low >> 16,
        low & 0xffff
    )
}

#[derive(Default)]
struct ParsedVersion {
    file_version: Option<String>,
    product_version: Option<String>,
    strings: BTreeMap<String, String>,
    string_locations: BTreeMap<String, Range>,
    translations: Vec<String>,
}

fn parse_version_payload(data: &[u8], base_offset: usize) -> Result<ParsedVersion, String> {
    let mut block_count = 0;
    let root = parse_version_block(data, 0, data.len(), 0, &mut block_count)?;
    if root.key != "VS_VERSION_INFO" {
        return Err(format!(
            "root key is {:?}, expected VS_VERSION_INFO",
            root.key
        ));
    }

    let mut parsed = ParsedVersion::default();
    if root.value.len() >= 52 && matches!(read_u32(root.value, 0), Ok(0xfeef04bd)) {
        parsed.file_version = Some(format_version(
            read_u32(root.value, 8).map_err(|_| "truncated VS_FIXEDFILEINFO")?,
            read_u32(root.value, 12).map_err(|_| "truncated VS_FIXEDFILEINFO")?,
        ));
        parsed.product_version = Some(format_version(
            read_u32(root.value, 16).map_err(|_| "truncated VS_FIXEDFILEINFO")?,
            read_u32(root.value, 20).map_err(|_| "truncated VS_FIXEDFILEINFO")?,
        ));
    }
    collect_version_children(&root, base_offset, &mut parsed);
    if parsed.file_version.is_none()
        && parsed.product_version.is_none()
        && parsed.strings.is_empty()
        && parsed.translations.is_empty()
    {
        return Err("VS_FIXEDFILEINFO is absent or has an invalid signature".into());
    }
    Ok(parsed)
}

struct VersionBlock<'a> {
    key: String,
    value: &'a [u8],
    value_range: std::ops::Range<usize>,
    children: Vec<VersionBlock<'a>>,
}

fn parse_version_block<'a>(
    data: &'a [u8],
    start: usize,
    parent_end: usize,
    depth: usize,
    count: &mut usize,
) -> Result<VersionBlock<'a>, String> {
    if depth > MAX_VERSION_DEPTH {
        return Err("nested block depth exceeds the safety bound".into());
    }
    *count = count.checked_add(1).ok_or("block count overflow")?;
    if *count > MAX_VERSION_BLOCKS {
        return Err("nested block count exceeds the safety bound".into());
    }
    let length = usize::from(read_u16(data, start).map_err(|_| "missing block length")?);
    let value_length = usize::from(
        read_u16(data, start.checked_add(2).ok_or("block header overflow")?)
            .map_err(|_| "missing value length")?,
    );
    let value_type = read_u16(data, start.checked_add(4).ok_or("block header overflow")?)
        .map_err(|_| "missing value type")?;
    if length < 6 {
        return Err("block length is smaller than its header".into());
    }
    let end = start.checked_add(length).ok_or("block extent overflows")?;
    if end > parent_end || end > data.len() {
        return Err("block extent exceeds its parent or payload".into());
    }
    let mut cursor = start + 6;
    let key = read_version_key(data, &mut cursor, end)?;
    cursor = align_version(cursor, end)?;
    let value_bytes = if value_type == 1 {
        value_length
            .checked_mul(2)
            .ok_or("string value length overflows")?
    } else {
        value_length
    };
    let value_start = cursor;
    let value_end = value_start
        .checked_add(value_bytes)
        .ok_or("value extent overflows")?;
    if value_end > end {
        return Err(format!("value for {key:?} exceeds block extent"));
    }
    cursor = align_version(value_end, end)?;
    let mut children = Vec::new();
    while cursor < end {
        if end - cursor < 2 || data[cursor..end].iter().all(|byte| *byte == 0) {
            break;
        }
        let child = parse_version_block(data, cursor, end, depth + 1, count)?;
        let child_end =
            cursor + usize::from(read_u16(data, cursor).map_err(|_| "missing child length")?);
        children.push(child);
        cursor = align_version(child_end, end)?;
    }
    Ok(VersionBlock {
        key,
        value: &data[value_start..value_end],
        value_range: value_start..value_end,
        children,
    })
}

fn read_version_key(data: &[u8], cursor: &mut usize, end: usize) -> Result<String, String> {
    let start = *cursor;
    while *cursor + 2 <= end {
        let unit = read_u16(data, *cursor).map_err(|_| "truncated UTF-16 key")?;
        *cursor += 2;
        if unit == 0 {
            let units = data[start..*cursor - 2]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            return String::from_utf16(&units).map_err(|_| "invalid UTF-16 key".into());
        }
    }
    Err("unterminated UTF-16 key".into())
}

fn align_version(offset: usize, end: usize) -> Result<usize, String> {
    let aligned = (offset + 3) & !3;
    if aligned > end {
        Err("alignment exceeds block extent".into())
    } else {
        Ok(aligned)
    }
}

fn collect_version_children(block: &VersionBlock<'_>, base: usize, parsed: &mut ParsedVersion) {
    if block.key == "Translation" {
        for pair in block.value.chunks_exact(4) {
            parsed.translations.push(format!(
                "{:04x}-{:04x}",
                u16::from_le_bytes([pair[2], pair[3]]),
                u16::from_le_bytes([pair[0], pair[1]])
            ));
        }
    } else if !block.value.is_empty()
        && block.key != "VS_VERSION_INFO"
        && block.key != "StringFileInfo"
        && block.key != "VarFileInfo"
        && block.key != "StringTable"
    {
        let units = block
            .value
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|unit| *unit != 0)
            .collect::<Vec<_>>();
        if let Ok(value) = String::from_utf16(&units) {
            parsed.strings.insert(block.key.clone(), value);
            parsed.string_locations.insert(
                block.key.clone(),
                Range {
                    offset: base + block.value_range.start,
                    bytes: block.value_range.end - block.value_range.start,
                },
            );
        }
    }
    for child in &block.children {
        collect_version_children(child, base, parsed);
    }
}

fn hash_range(bytes: &[u8], range: &Range, cancellation: &Cancellation) -> Result<String, Error> {
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < range.bytes {
        check_cancellation(cancellation)?;
        let end = range.bytes.min(offset.saturating_add(1024 * 1024));
        hash.update(&bytes[range.offset + offset..range.offset + end]);
        offset = end;
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn read_icon_groups(parser: &mut Parser<'_>) -> Result<Vec<IconGroup>, Error> {
    let mut images_by_id = HashMap::<u32, Vec<usize>>::new();
    for resource in &parser.resources {
        if matches!(&resource.r#type, Identity::Id { id: 3 })
            && let Identity::Id { id } = &resource.name
        {
            images_by_id.entry(*id).or_default().push(resource.index);
        }
    }

    let group_indices = parser
        .resources
        .iter()
        .filter(|resource| matches!(&resource.r#type, Identity::Id { id: 14 }))
        .map(|resource| resource.index)
        .collect::<Vec<_>>();
    let mut groups = Vec::with_capacity(group_indices.len());
    for resource_index in group_indices {
        let group = parser.resources[resource_index].clone();
        let offset = group.payload.location.offset;
        let size = group.payload.location.bytes;
        if size < 6 {
            return Err(Error::Malformed("malformed RT_GROUP_ICON header"));
        }
        let count = usize::from(read_u16(parser.bytes, offset + 4)?);
        let expected_size = icon_group_size(count).ok_or(Error::Malformed(
            "RT_GROUP_ICON image count overflows its bounded extent",
        ))?;
        if size != expected_size {
            return Err(Error::Malformed(
                "RT_GROUP_ICON length does not match its image count",
            ));
        }
        if read_u16(parser.bytes, offset)? != 0 || read_u16(parser.bytes, offset + 2)? != 1 {
            return Err(Error::Malformed("malformed RT_GROUP_ICON header"));
        }

        let mut images = Vec::with_capacity(count);
        for index in 0..count {
            if index % 128 == 0 {
                parser.check_active()?;
            }
            let at = icon_image_offset(offset, index).ok_or(Error::Malformed(
                "RT_GROUP_ICON image source range overflows",
            ))?;
            let resource_id = read_u16(parser.bytes, at + 12)?;
            let candidates = images_by_id
                .get(&u32::from(resource_id))
                .map(Vec::as_slice)
                .unwrap_or_default();
            parser.ensure_capacity(302 + candidates.len() * 11)?;
            let language_candidates = candidates
                .iter()
                .copied()
                .filter(|candidate| {
                    same_identity(&parser.resources[*candidate].language, &group.language)
                })
                .collect::<Vec<_>>();
            let (reference, same_language) =
                match (candidates.is_empty(), language_candidates.as_slice()) {
                    (true, _) => (IconReference::Missing, None),
                    (false, []) => (IconReference::NoLanguageMatch, None),
                    (false, [_]) => (
                        IconReference::Resolved,
                        language_candidates.first().copied(),
                    ),
                    (false, _) => (IconReference::Ambiguous, None),
                };
            let declared_bytes = read_u32(parser.bytes, at + 8)?;
            let image = IconImage {
                location: Range {
                    offset: at,
                    bytes: 14,
                },
                width: parser.bytes[at],
                height: parser.bytes[at + 1],
                color_count: parser.bytes[at + 2],
                reserved: parser.bytes[at + 3],
                planes: read_u16(parser.bytes, at + 4)?,
                bit_count: read_u16(parser.bytes, at + 6)?,
                declared_bytes,
                resource_id,
                candidate_resource_indices: candidates.to_vec(),
                language_candidate_resource_indices: language_candidates,
                reference,
                resolved_location: same_language
                    .map(|candidate| parser.resources[candidate].payload.location.clone()),
                same_language_resource_index: same_language,
                size_matches: same_language.map(|candidate| {
                    parser.resources[candidate].payload.location.bytes == declared_bytes as usize
                }),
            };
            parser.account(&image)?;
            images.push(image);
        }
        parser.account(&IconGroup {
            resource_index,
            images: Vec::new(),
        })?;
        groups.push(IconGroup {
            resource_index,
            images,
        });
    }
    Ok(groups)
}

fn icon_group_size(count: usize) -> Option<usize> {
    count.checked_mul(14)?.checked_add(6)
}

fn icon_image_offset(group_offset: usize, index: usize) -> Option<usize> {
    group_offset
        .checked_add(6)?
        .checked_add(index.checked_mul(14)?)
}

fn read_icons(parser: &Parser<'_>) -> (Vec<IconResource>, Vec<String>) {
    let mut icons = Vec::new();
    let mut issues = Vec::new();
    for resource in &parser.resources {
        if !matches!(&resource.r#type, Identity::Id { id: 3 }) {
            continue;
        }
        let range = &resource.payload.location;
        let Some(raw_bytes) = parser
            .bytes
            .get(range.offset..range.offset.saturating_add(range.bytes))
        else {
            issues.push(format!(
                "RT_ICON resource {} is truncated; image metadata remains unavailable.",
                resource.index
            ));
            continue;
        };
        if raw_bytes.is_empty() || raw_bytes.len() > MAX_MANIFEST_BYTES {
            issues.push(format!("RT_ICON resource {} is empty or exceeds the 1 MiB image bound; image metadata remains unavailable.", resource.index));
            continue;
        }
        let (format, width, height, bit_count, malformed) = icon_header(raw_bytes);
        if let Some(reason) = &malformed {
            issues.push(format!(
                "RT_ICON resource {} has malformed {} header: {reason}.",
                resource.index, format
            ));
            continue;
        }
        icons.push(IconResource {
            resource_index: resource.index,
            resource_id: resource.name.clone(),
            location: range.clone(),
            raw_bytes: raw_bytes.to_vec(),
            format,
            width,
            height,
            bit_count,
            malformed,
        });
    }
    (icons, issues)
}

fn read_cursors(parser: &Parser<'_>) -> (Vec<CursorResource>, Vec<String>) {
    let mut cursors = Vec::new();
    let mut issues = Vec::new();
    for resource in &parser.resources {
        if !matches!(&resource.r#type, Identity::Id { id: 1 }) {
            continue;
        }
        let range = &resource.payload.location;
        let Some(raw_bytes) = parser
            .bytes
            .get(range.offset..range.offset.saturating_add(range.bytes))
        else {
            issues.push(format!(
                "RT_CURSOR resource {} is truncated; cursor metadata remains unavailable.",
                resource.index
            ));
            continue;
        };
        if raw_bytes.is_empty() || raw_bytes.len() > MAX_MANIFEST_BYTES {
            issues.push(format!(
                "RT_CURSOR resource {} is empty or exceeds the 1 MiB image bound; cursor metadata remains unavailable.",
                resource.index
            ));
            continue;
        }
        let (format, width, height, bit_count, malformed) = icon_header(raw_bytes);
        if let Some(reason) = &malformed {
            issues.push(format!(
                "RT_CURSOR resource {} has malformed {} header: {reason}.",
                resource.index, format
            ));
            continue;
        }
        cursors.push(CursorResource {
            resource_index: resource.index,
            resource_id: resource.name.clone(),
            location: range.clone(),
            raw_bytes: raw_bytes.to_vec(),
            format,
            width,
            height,
            bit_count,
            hotspot_x: None,
            hotspot_y: None,
            malformed,
        });
    }
    (cursors, issues)
}

fn icon_header(
    data: &[u8],
) -> (
    &'static str,
    Option<u32>,
    Option<u32>,
    Option<u16>,
    Option<String>,
) {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        if data.len() < 26 || &data[12..16] != b"IHDR" {
            return ("png", None, None, None, Some("truncated IHDR".to_owned()));
        }
        let width = u32::from_be_bytes(data[16..20].try_into().unwrap());
        let height = u32::from_be_bytes(data[20..24].try_into().unwrap());
        let depth = u16::from(data[24]);
        return ("png", Some(width), Some(height), Some(depth), None);
    }
    if data.len() < 40 {
        return (
            "dib",
            None,
            None,
            None,
            Some("truncated BITMAPINFOHEADER".to_owned()),
        );
    }
    let header_size = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if header_size < 40 || usize::try_from(header_size).unwrap_or(usize::MAX) > data.len() {
        return (
            "dib",
            None,
            None,
            None,
            Some("unsupported DIB header size".to_owned()),
        );
    }
    let width = i32::from_le_bytes(data[4..8].try_into().unwrap()).unsigned_abs();
    let full_height = i32::from_le_bytes(data[8..12].try_into().unwrap()).unsigned_abs();
    if full_height < 2 {
        return (
            "dib",
            Some(width),
            Some(full_height),
            Some(u16::from_le_bytes(data[14..16].try_into().unwrap())),
            Some("DIB height does not contain icon and mask planes".to_owned()),
        );
    }
    (
        "dib",
        Some(width),
        Some(full_height / 2),
        Some(u16::from_le_bytes(data[14..16].try_into().unwrap())),
        None,
    )
}

fn read_cursor_groups(parser: &mut Parser<'_>) -> Result<Vec<CursorGroup>, Error> {
    let mut cursors = HashMap::<u32, Vec<usize>>::new();
    for resource in &parser.resources {
        if matches!(&resource.r#type, Identity::Id { id: 1 })
            && let Identity::Id { id } = &resource.name
        {
            cursors.entry(*id).or_default().push(resource.index);
        }
    }
    let groups = parser
        .resources
        .iter()
        .filter(|resource| matches!(&resource.r#type, Identity::Id { id: 12 }))
        .map(|resource| resource.index)
        .collect::<Vec<_>>();
    let mut output = Vec::with_capacity(groups.len());
    for resource_index in groups {
        let group = parser.resources[resource_index].clone();
        let offset = group.payload.location.offset;
        let size = group.payload.location.bytes;
        if size < 6 {
            return Err(Error::Malformed("malformed RT_GROUP_CURSOR header"));
        }
        let count = usize::from(read_u16(parser.bytes, offset + 4)?);
        let Some(expected_size) = icon_group_size(count) else {
            return Err(Error::Malformed(
                "RT_GROUP_CURSOR image count overflows its directory size",
            ));
        };
        if size != expected_size {
            return Err(Error::Malformed(
                "RT_GROUP_CURSOR length does not match its image count",
            ));
        }
        if read_u16(parser.bytes, offset)? != 0 || read_u16(parser.bytes, offset + 2)? != 2 {
            return Err(Error::Malformed("malformed RT_GROUP_CURSOR header"));
        }
        let mut images = Vec::with_capacity(count);
        for index in 0..count {
            let Some(at) = icon_image_offset(offset, index) else {
                return Err(Error::Malformed("RT_GROUP_CURSOR image offset overflows"));
            };
            let resource_id = read_u16(parser.bytes, at + 12)?;
            let candidates = cursors
                .get(&u32::from(resource_id))
                .map(Vec::as_slice)
                .unwrap_or_default();
            let language_candidates = candidates
                .iter()
                .copied()
                .filter(|candidate| {
                    same_identity(&parser.resources[*candidate].language, &group.language)
                })
                .collect::<Vec<_>>();
            let (reference, same_language) =
                match (candidates.is_empty(), language_candidates.as_slice()) {
                    (true, _) => (IconReference::Missing, None),
                    (false, []) => (IconReference::NoLanguageMatch, None),
                    (false, [_]) => (
                        IconReference::Resolved,
                        language_candidates.first().copied(),
                    ),
                    (false, _) => (IconReference::Ambiguous, None),
                };
            let declared_bytes = read_u32(parser.bytes, at + 8)?;
            let image = CursorImage {
                location: Range {
                    offset: at,
                    bytes: 14,
                },
                width: parser.bytes[at],
                height: parser.bytes[at + 1],
                color_count: parser.bytes[at + 2],
                reserved: parser.bytes[at + 3],
                hotspot_x: read_u16(parser.bytes, at + 4)?,
                hotspot_y: read_u16(parser.bytes, at + 6)?,
                declared_bytes,
                resource_id,
                candidate_resource_indices: candidates.to_vec(),
                same_language_resource_index: same_language,
                resolved_location: same_language
                    .map(|candidate| parser.resources[candidate].payload.location.clone()),
                reference,
                size_matches: same_language.map(|candidate| {
                    parser.resources[candidate].payload.location.bytes == declared_bytes as usize
                }),
            };
            parser.account(&image)?;
            images.push(image);
        }
        parser.account(&CursorGroup {
            resource_index,
            images: Vec::new(),
        })?;
        output.push(CursorGroup {
            resource_index,
            images,
        });
    }
    Ok(output)
}

fn read_bitmaps(parser: &Parser<'_>) -> (Vec<BitmapResource>, Vec<String>) {
    let mut bitmaps = Vec::new();
    let mut issues = Vec::new();
    for resource in &parser.resources {
        if !matches!(&resource.r#type, Identity::Id { id: 2 }) {
            continue;
        }
        let range = &resource.payload.location;
        let Some(data) = parser
            .bytes
            .get(range.offset..range.offset.saturating_add(range.bytes))
        else {
            issues.push(format!(
                "RT_BITMAP resource {} is truncated; bitmap metadata remains unavailable.",
                resource.index
            ));
            continue;
        };
        match parse_bitmap(data, range.offset, resource.index, range.clone()) {
            Ok(bitmap) => bitmaps.push(bitmap),
            Err(reason) => issues.push(format!("RT_BITMAP resource {} is malformed or unsupported: {reason}; bitmap metadata remains unavailable.", resource.index)),
        }
    }
    (bitmaps, issues)
}

fn parse_bitmap(
    data: &[u8],
    base: usize,
    resource_index: usize,
    location: Range,
) -> Result<BitmapResource, String> {
    let (layout, header_offset, declared_file_bytes) =
        if data.len() >= 14 && data[0] == b'B' && data[1] == b'M' {
            let file_size = u32::from_le_bytes(
                data[2..6]
                    .try_into()
                    .map_err(|_| "truncated bitmap file header")?,
            );
            ("bitmap_file", 14usize, Some(file_size))
        } else {
            ("resource_dib", 0usize, None)
        };
    if data.len() < header_offset + 40 {
        return Err("DIB header is truncated".to_owned());
    }
    let header_size =
        u32::from_le_bytes(data[header_offset..header_offset + 4].try_into().unwrap());
    if header_size < 40
        || usize::try_from(header_size).unwrap_or(usize::MAX) > data.len() - header_offset
    {
        return Err(format!("unsupported DIB header size {header_size}"));
    }
    let at = header_offset;
    Ok(BitmapResource {
        resource_index,
        layout,
        location,
        header_location: Range {
            offset: base + at,
            bytes: header_size as usize,
        },
        width: i32::from_le_bytes(data[at + 4..at + 8].try_into().unwrap()),
        height: i32::from_le_bytes(data[at + 8..at + 12].try_into().unwrap()),
        planes: u16::from_le_bytes(data[at + 12..at + 14].try_into().unwrap()),
        bit_count: u16::from_le_bytes(data[at + 14..at + 16].try_into().unwrap()),
        compression: u32::from_le_bytes(data[at + 16..at + 20].try_into().unwrap()),
        declared_image_bytes: u32::from_le_bytes(data[at + 20..at + 24].try_into().unwrap()),
        declared_file_bytes,
    })
}

fn read_fonts(parser: &Parser<'_>) -> (Vec<FontResource>, Vec<String>) {
    let mut fonts = Vec::new();
    let mut issues = Vec::new();
    for resource in &parser.resources {
        let kind = match &resource.r#type {
            Identity::Id { id: 7 } => "fontdir",
            Identity::Id { id: 8 } => "font",
            _ => continue,
        };
        let range = &resource.payload.location;
        let Some(data) = parser
            .bytes
            .get(range.offset..range.offset.saturating_add(range.bytes))
        else {
            issues.push(format!(
                "RT_{} resource {} is truncated; font metadata remains unavailable.",
                kind.to_uppercase(),
                resource.index
            ));
            continue;
        };
        let (count, ids, entry_locations) = if kind == "fontdir" {
            if data.len() < 2 {
                issues.push(format!(
                    "RT_FONTDIR resource {} is malformed: missing entry count; font metadata remains unavailable.",
                    resource.index
                ));
                continue;
            }
            let count = u16::from_le_bytes([data[0], data[1]]);
            let required = 2usize.saturating_add(usize::from(count).saturating_mul(2));
            if count > 4096 || required > data.len() {
                issues.push(format!(
                    "RT_FONTDIR resource {} is malformed: entry table is truncated or exceeds its bound; font metadata remains unavailable.",
                    resource.index
                ));
                continue;
            }
            let ids = (0..usize::from(count))
                .map(|index| u16::from_le_bytes([data[2 + index * 2], data[3 + index * 2]]))
                .collect();
            let entry_locations = (0..usize::from(count))
                .map(|index| Range {
                    offset: range.offset + 2 + index * 2,
                    bytes: 2,
                })
                .collect();
            (Some(count), ids, entry_locations)
        } else {
            (None, Vec::new(), Vec::new())
        };
        fonts.push(FontResource {
            resource_index: resource.index,
            kind,
            location: range.clone(),
            header_location: Range {
                offset: range.offset,
                bytes: if kind == "fontdir" {
                    2
                } else {
                    range.bytes.min(4)
                },
            },
            declared_bytes: range.bytes,
            declared_entry_count: count,
            font_id: resource.name.clone(),
            font_name: None,
            associated_resource_ids: ids,
            entry_locations,
        });
    }
    (fonts, issues)
}

fn same_identity(left: &Identity, right: &Identity) -> bool {
    match (left, right) {
        (Identity::Id { id: left }, Identity::Id { id: right }) => left == right,
        (
            Identity::Name {
                utf16le_hex: left, ..
            },
            Identity::Name {
                utf16le_hex: right, ..
            },
        ) => left == right,
        _ => false,
    }
}

fn identity_key(identity: &Identity) -> String {
    match identity {
        Identity::Id { id } => format!("id:{id}"),
        Identity::Name { utf16le_hex, .. } => format!("name:{utf16le_hex}"),
    }
}

fn reject_overlapping_ranges(ranges: &mut [OccupiedRange]) -> Result<(), Error> {
    ranges.sort_unstable_by(|left, right| {
        left.range
            .offset
            .cmp(&right.range.offset)
            .then_with(|| right.range.bytes.cmp(&left.range.bytes))
    });
    let mut previous: Option<OccupiedRange> = None;
    for current in ranges {
        current
            .range
            .offset
            .checked_add(current.range.bytes)
            .ok_or(Error::Malformed("resource byte range overflows"))?;
        if let Some(previous) = previous {
            let previous_end = previous
                .range
                .offset
                .checked_add(previous.range.bytes)
                .ok_or(Error::Malformed("resource byte range overflows"))?;
            if current.range.offset < previous_end
                && (current.range.offset != previous.range.offset
                    || current.range.bytes != previous.range.bytes
                    || current.kind != previous.kind)
            {
                return Err(Error::Malformed(
                    "non-identical resource byte ranges overlap",
                ));
            }
        }
        previous = Some(current.clone());
    }
    Ok(())
}

fn map_layout_error(error: crate::ContainerError) -> Error {
    match error {
        crate::ContainerError::Malformed(reason) => Error::Malformed(reason),
        crate::ContainerError::Unsupported(reason) => Error::Unsupported(reason),
        crate::ContainerError::StructureLimit => Error::ResourceLimit {
            boundary: "memory",
            maximum: 16 * 1024 * 1024,
            reason: "Native structure exceeds the 16 MiB decoding budget.",
        },
    }
}

fn check_cancellation(cancellation: &Cancellation) -> Result<(), Error> {
    match cancellation.reason() {
        Some(reason) => Err(Error::Cancelled(reason.to_owned())),
        None => Ok(()),
    }
}

fn checked_range(bytes: &[u8], offset: usize, length: usize) -> Result<(), Error> {
    let end = offset
        .checked_add(length)
        .ok_or(Error::Malformed("PE range overflows"))?;
    if end > bytes.len() {
        return Err(Error::Malformed("PE range leaves the artifact"));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    checked_range(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    checked_range(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[usize::from(byte >> 4)] as char);
        result.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    result
}

struct LengthWriter {
    length: usize,
    maximum: usize,
    exceeded: bool,
}

impl io::Write for LengthWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.length) {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized PE resource result exceeds budget",
            ));
        }
        self.length += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_length<T: Serialize>(value: &T, maximum: usize) -> Result<usize, Error> {
    let mut writer = LengthWriter {
        length: 0,
        maximum,
        exceeded: false,
    };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(writer.length),
        Err(error) if writer.exceeded => Err(Error::ResourceLimit {
            boundary: "memory",
            maximum: MAX_METADATA_BYTES,
            reason: "PE resource result exceeds the 8 MiB allocation budget.",
        }),
        Err(error) => Err(Error::Encoding(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::{Artifact, Error, Identity, Input, MAX_DIRECTORY_ENTRIES, read};
    use rea_core::cancellation::Cancellation;
    use sha2::{Digest, Sha256};

    fn fixture(plus: bool) -> Vec<u8> {
        let mut bytes = vec![0; 0x600];
        write_u16(&mut bytes, 0, 0x5a4d);
        write_u32(&mut bytes, 60, 0x80);
        write_u32(&mut bytes, 0x80, 0x0000_4550);
        write_u16(&mut bytes, 0x84, if plus { 0x8664 } else { 0x014c });
        write_u16(&mut bytes, 0x86, 1);

        let optional_size: usize = if plus { 240 } else { 224 };
        let optional = 0x98;
        write_u16(&mut bytes, 0x94, optional_size as u16);
        write_u16(&mut bytes, optional, if plus { 0x20b } else { 0x10b });
        write_u32(&mut bytes, optional + 60, 0x400);
        write_u32(&mut bytes, optional + if plus { 108 } else { 92 }, 16);
        let resource_directory = optional + if plus { 128 } else { 112 };
        write_u32(&mut bytes, resource_directory, 0x2000);
        write_u32(&mut bytes, resource_directory + 4, 92);

        let section = optional + optional_size;
        write_u32(&mut bytes, section + 8, 0x200);
        write_u32(&mut bytes, section + 12, 0x2000);
        write_u32(&mut bytes, section + 16, 0x200);
        write_u32(&mut bytes, section + 20, 0x400);

        write_u16(&mut bytes, 0x400 + 14, 1);
        write_u32(&mut bytes, 0x400 + 16, 10);
        write_u32(&mut bytes, 0x400 + 20, 0x8000_0018);
        write_u16(&mut bytes, 0x400 + 24 + 14, 1);
        write_u32(&mut bytes, 0x400 + 24 + 16, 7);
        write_u32(&mut bytes, 0x400 + 24 + 20, 0x8000_0030);
        write_u16(&mut bytes, 0x400 + 48 + 14, 1);
        write_u32(&mut bytes, 0x400 + 48 + 16, 1033);
        write_u32(&mut bytes, 0x400 + 48 + 20, 72);
        write_u32(&mut bytes, 0x400 + 72, 0x2058);
        write_u32(&mut bytes, 0x400 + 72 + 4, 4);
        write_u32(&mut bytes, 0x400 + 72 + 8, 65001);
        bytes[0x400 + 88..0x400 + 92].copy_from_slice(b"ICON");
        bytes
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn append_utf16(bytes: &mut Vec<u8>, value: &str) {
        for unit in value.encode_utf16().chain(std::iter::once(0)) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
    }

    fn input(max_entries: usize) -> Input {
        Input {
            max_file_bytes: 1024 * 1024,
            max_entries,
        }
    }

    fn artifact(bytes: &[u8]) -> Artifact {
        Artifact {
            path: "/fixtures/example.exe".into(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            bytes: bytes.len(),
        }
    }

    #[test]
    fn preserves_complete_pe32_and_pe32_plus_resource_facts() {
        for plus in [false, true] {
            let bytes = fixture(plus);
            let report = read(
                &bytes,
                artifact(&bytes),
                input(MAX_DIRECTORY_ENTRIES),
                &Cancellation::default(),
            )
            .unwrap();

            assert_eq!(report.format, if plus { "pe32-plus" } else { "pe32" });
            assert_eq!(report.machine, if plus { 0x8664 } else { 0x014c });
            assert_eq!(report.coverage.status, "complete");
            assert_eq!(report.coverage.examined_entries, 3);
            assert_eq!(report.resources.len(), 1);
            assert_eq!(report.resources[0].r#type, Identity::Id { id: 10 });
            assert_eq!(report.resources[0].name, Identity::Id { id: 7 });
            assert_eq!(report.resources[0].language, Identity::Id { id: 1033 });
            assert_eq!(report.resources[0].payload.location.offset, 0x458);
            assert_eq!(report.resources[0].payload.location.bytes, 4);
            assert_eq!(
                report.resources[0].payload.sha256,
                format!("{:x}", Sha256::digest(b"ICON"))
            );
        }
    }

    #[test]
    fn preserves_named_resource_identity_without_double_budget_accounting() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x10c, 0xa8);
        write_u16(&mut bytes, 0x400 + 12, 1);
        write_u16(&mut bytes, 0x400 + 14, 0);
        write_u32(&mut bytes, 0x400 + 16, 0x8000_00a0);
        write_u16(&mut bytes, 0x400 + 0xa0, 3);
        bytes[0x400 + 0xa2..0x400 + 0xa8].copy_from_slice(&[b'N', 0, b'A', 0, b'M', 0]);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();

        assert_eq!(
            report.resources[0].r#type,
            Identity::Name {
                name: "NAM".into(),
                utf16le_hex: "4e0041004d00".into(),
                location: super::Range {
                    offset: 0x4a0,
                    bytes: 8,
                },
            }
        );
    }

    #[test]
    fn extracts_manifest_identity_range_code_page_and_raw_xml() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 24);
        bytes[0x458..0x45c].copy_from_slice(b"<m/>");

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();

        assert_eq!(report.manifests.len(), 1);
        let manifest = &report.manifests[0];
        assert_eq!(manifest.resource_index, 0);
        assert_eq!(manifest.r#type, Identity::Id { id: 24 });
        assert_eq!(manifest.name, Identity::Id { id: 7 });
        assert_eq!(manifest.language, Identity::Id { id: 1033 });
        assert_eq!(manifest.code_page, 65001);
        assert_eq!(manifest.location.offset, 0x458);
        assert_eq!(manifest.location.bytes, 4);
        assert_eq!(manifest.raw_xml, b"<m/>");
        assert_eq!(manifest.encoding, "utf8");
        assert_eq!(manifest.text.as_deref(), Some("<m/>"));
        assert_eq!(manifest.decode_issue, None);
    }

    #[test]
    fn decodes_utf16_manifest_text_while_retaining_raw_bytes() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 24);
        write_u32(&mut bytes, 0x400 + 72 + 4, 8);
        bytes[0x458..0x460].copy_from_slice(&[0xff, 0xfe, b'<', 0, b'm', 0, b'>', 0]);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();

        let manifest = &report.manifests[0];
        assert_eq!(manifest.encoding, "utf16le");
        assert_eq!(manifest.text.as_deref(), Some("<m>"));
        assert_eq!(manifest.raw_xml, [0xff, 0xfe, b'<', 0, b'm', 0, b'>', 0]);
        assert_eq!(manifest.decode_issue, None);
    }

    #[test]
    fn retains_undecodable_manifest_bytes_with_explicit_issue() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 24);
        write_u32(&mut bytes, 0x400 + 72 + 4, 2);
        bytes[0x458..0x45a].copy_from_slice(&[0xff, 0x80]);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();

        let manifest = &report.manifests[0];
        assert_eq!(manifest.encoding, "unknown");
        assert_eq!(manifest.text, None);
        assert!(manifest.decode_issue.is_some());
        assert_eq!(manifest.raw_xml, [0xff, 0x80]);
        assert!(
            report
                .limitations
                .iter()
                .any(|issue| issue.contains("undecodable text"))
        );
    }

    #[test]
    fn reports_empty_manifest_payload_without_claiming_xml() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 24);
        write_u32(&mut bytes, 0x400 + 72 + 4, 0);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();

        assert!(report.manifests.is_empty());
        assert!(
            report
                .limitations
                .iter()
                .any(|issue| issue.contains("RT_MANIFEST resource 0 has an empty payload"))
        );
    }

    #[test]
    fn preserves_missing_group_icon_reference_as_unknown() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 14);
        write_u32(&mut bytes, 0x400 + 72 + 4, 20);
        write_u16(&mut bytes, 0x458, 0);
        write_u16(&mut bytes, 0x45a, 1);
        write_u16(&mut bytes, 0x45c, 1);
        write_u32(&mut bytes, 0x45e + 8, 4);
        write_u16(&mut bytes, 0x45e + 12, 7);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();

        let image = &report.icon_groups[0].images[0];
        assert!(matches!(image.reference, super::IconReference::Missing));
        assert!(image.candidate_resource_indices.is_empty());
        assert!(image.same_language_resource_index.is_none());
        assert!(image.resolved_location.is_none());
        assert_eq!(image.declared_bytes, 4);
    }

    #[test]
    fn rejects_malformed_group_icon_directory_before_projecting_images() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 14);
        write_u32(&mut bytes, 0x400 + 72 + 4, 7);

        assert!(matches!(
            read(
                &bytes,
                artifact(&bytes),
                input(MAX_DIRECTORY_ENTRIES),
                &Cancellation::default(),
            ),
            Err(Error::Malformed(
                "RT_GROUP_ICON length does not match its image count"
            ))
        ));
    }

    #[test]
    fn decodes_empty_and_non_ascii_string_block_entries() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 6);
        write_u32(&mut bytes, 0x400 + 72 + 4, 32);
        bytes[0x458..0x478].fill(0);
        write_u16(&mut bytes, 0x458 + 2, 1);
        write_u16(&mut bytes, 0x458 + 4, 0x00e9);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();

        assert_eq!(report.strings.len(), 16);
        assert_eq!(report.strings[0].string_id, 96);
        assert_eq!(report.strings[0].value, "");
        assert_eq!(report.strings[0].location.offset, 0x458);
        assert_eq!(report.strings[0].location.bytes, 2);
        assert_eq!(report.strings[0].value_location.offset, 0x45a);
        assert_eq!(report.strings[0].value_location.bytes, 0);
        assert_eq!(report.strings[1].string_id, 97);
        assert_eq!(report.strings[1].value, "é");
        assert_eq!(report.strings[1].value_location.offset, 0x45c);
        assert_eq!(report.strings[1].value_location.bytes, 2);
        assert_eq!(report.strings[1].language, Identity::Id { id: 1033 });
        assert_eq!(report.strings[1].code_page, 65001);
    }

    #[test]
    fn reports_truncated_string_entry_without_fabricating_value() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 6);
        write_u32(&mut bytes, 0x400 + 72 + 4, 3);
        bytes[0x458..0x45b].copy_from_slice(&[2, 0, b'A']);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();

        assert_eq!(report.strings.len(), 1);
        assert!(!report.strings[0].complete);
        assert_eq!(report.strings[0].raw_utf16le, &[2, 0, b'A']);
        assert_eq!(report.strings[0].value_location.offset, 0x45a);
        assert_eq!(report.strings[0].value_location.bytes, 1);
        assert!(
            report
                .limitations
                .iter()
                .any(|issue| issue.contains("RT_STRING resource 0 entry 0 is truncated"))
        );
    }

    #[test]
    fn decodes_standard_dialog_template_and_control() {
        let mut bytes = fixture(false);
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x40u32.to_le_bytes());
        payload.extend_from_slice(&0x10u32.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        for value in [1i16, 2, 100, 50] {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0xffffu16.to_le_bytes());
        payload.extend_from_slice(&0x80u16.to_le_bytes());
        append_utf16(&mut payload, "D");
        payload.extend_from_slice(&9u16.to_le_bytes());
        append_utf16(&mut payload, "Arial");
        while payload.len() % 4 != 0 {
            payload.push(0);
        }
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());
        for value in [3i16, 4, 20, 10] {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        payload.extend_from_slice(&7u16.to_le_bytes());
        payload.extend_from_slice(&0xffffu16.to_le_bytes());
        payload.extend_from_slice(&0x82u16.to_le_bytes());
        append_utf16(&mut payload, "é");
        payload.extend_from_slice(&3u16.to_le_bytes());
        payload.extend_from_slice(&[1, 2, 3]);
        write_u32(&mut bytes, 0x400 + 16, 5);
        write_u32(&mut bytes, 0x400 + 72 + 4, payload.len() as u32);
        bytes[0x458..0x458 + payload.len()].copy_from_slice(&payload);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        let dialog = &report.dialogs[0];
        assert_eq!(dialog.kind, "dialog");
        assert_eq!(dialog.style, 0x40);
        assert_eq!(dialog.ex_style, 0x10);
        assert!(matches!(dialog.menu, super::DialogValue::None));
        assert!(matches!(
            dialog.class,
            super::DialogValue::Ordinal { value: 0x80 }
        ));
        assert!(matches!(
            &dialog.title,
            super::DialogValue::Text { value, .. } if value == "D"
        ));
        assert!(matches!(
            &dialog.title,
            super::DialogValue::Text { location, .. } if location.offset >= 0x458
        ));
        assert_eq!(dialog.controls.len(), 1);
        assert_eq!(dialog.controls[0].identifier, 7);
        assert!(matches!(
            &dialog.controls[0].title,
            super::DialogValue::Text { value, .. } if value == "é"
        ));
        assert!(matches!(
            &dialog.controls[0].title,
            super::DialogValue::Text { location, .. } if location.bytes >= 4
        ));
        assert_eq!(dialog.controls[0].creation_data_bytes, 3);
    }

    #[test]
    fn decodes_extended_dialog_template_and_32_bit_control_id() {
        let mut bytes = fixture(false);
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&0xffffu16.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&0x20u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        for value in [5i16, 6, 70, 40] {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        append_utf16(&mut payload, "M");
        payload.extend_from_slice(&0u16.to_le_bytes());
        append_utf16(&mut payload, "X");
        while payload.len() % 4 != 0 {
            payload.push(0);
        }
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        for value in [1i16, 2, 30, 12] {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        payload.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        append_utf16(&mut payload, "C");
        payload.extend_from_slice(&0xffffu16.to_le_bytes());
        payload.extend_from_slice(&0x99u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        write_u32(&mut bytes, 0x400 + 16, 5);
        write_u32(&mut bytes, 0x400 + 72 + 4, payload.len() as u32);
        bytes[0x458..0x458 + payload.len()].copy_from_slice(&payload);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        let dialog = &report.dialogs[0];
        assert_eq!(dialog.kind, "dialogex");
        assert_eq!(dialog.ex_style, 0x20);
        assert_eq!(dialog.controls[0].identifier, 0x1234_5678);
        assert_eq!(dialog.controls[0].creation_data_bytes, 0);
        assert!(matches!(
            &dialog.controls[0].title,
            super::DialogValue::Ordinal { value: 0x99 }
        ));
    }

    #[test]
    fn reports_truncated_dialog_without_returning_partial_template() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 5);
        write_u32(&mut bytes, 0x400 + 72 + 4, 4);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();

        assert!(report.dialogs.is_empty());
        assert!(
            report
                .limitations
                .iter()
                .any(|issue| issue.contains("RT_DIALOG resource 0 is malformed"))
        );
    }

    #[test]
    fn decodes_standard_menu_nesting_and_end_markers() {
        let mut bytes = fixture(false);
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&4u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&7u16.to_le_bytes());
        append_utf16(&mut payload, "Open");
        payload.extend_from_slice(&0x10u32.to_le_bytes());
        append_utf16(&mut payload, "Sub");
        payload.extend_from_slice(&0x80u32.to_le_bytes());
        payload.extend_from_slice(&8u16.to_le_bytes());
        append_utf16(&mut payload, "Close");
        write_u32(&mut bytes, 0x400 + 16, 4);
        write_u32(&mut bytes, 0x400 + 72 + 4, payload.len() as u32);
        bytes[0x458..0x458 + payload.len()].copy_from_slice(&payload);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        let menu = &report.menus[0];
        assert_eq!(menu.kind, "menu");
        assert_eq!(menu.items.len(), 3);
        assert_eq!(menu.items[0].identifier, Some(7));
        assert_eq!(menu.items[1].depth, 0);
        assert_eq!(menu.items[2].depth, 1);
        assert!(menu.items[1].flags & 0x10 != 0);
        assert!(menu.items[2].flags & 0x80 != 0);
    }

    #[test]
    fn decodes_menuex_item_ids_and_reports_truncation() {
        let mut bytes = fixture(false);
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&4u16.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&9u32.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        append_utf16(&mut payload, "Item");
        write_u32(&mut bytes, 0x400 + 16, 4);
        write_u32(&mut bytes, 0x400 + 72 + 4, payload.len() as u32);
        bytes[0x458..0x458 + payload.len()].copy_from_slice(&payload);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        assert_eq!(report.menus[0].kind, "menuex");
        assert_eq!(report.menus[0].items[0].identifier, Some(9));

        write_u32(&mut bytes, 0x400 + 72 + 4, 18);
        let truncated = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        assert!(truncated.menus.is_empty());
        assert!(
            truncated
                .limitations
                .iter()
                .any(|issue| issue.contains("RT_MENUEX resource 0 is malformed"))
        );
    }

    #[test]
    fn decodes_accelerator_entries_and_last_marker() {
        let mut bytes = fixture(false);
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&(b'A' as u16).to_le_bytes());
        payload.extend_from_slice(&7u16.to_le_bytes());
        payload.extend_from_slice(&0x80u16.to_le_bytes());
        payload.extend_from_slice(&(b'B' as u16).to_le_bytes());
        payload.extend_from_slice(&9u16.to_le_bytes());
        write_u32(&mut bytes, 0x400 + 16, 9);
        write_u32(&mut bytes, 0x400 + 72 + 4, payload.len() as u32);
        bytes[0x458..0x458 + payload.len()].copy_from_slice(&payload);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        let table = &report.accelerators[0];
        assert_eq!(table.entries.len(), 2);
        assert_eq!(table.entries[0].key, b'A' as u16);
        assert_eq!(table.entries[0].command, 7);
        assert!(!table.entries[0].is_last);
        assert!(table.entries[1].is_last);
        assert_eq!(table.entries[1].location.offset, 0x45e);
    }

    #[test]
    fn rejects_accelerator_table_without_last_marker() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 9);
        write_u32(&mut bytes, 0x400 + 72 + 4, 6);
        bytes[0x458..0x45e].copy_from_slice(&[1, 0, b'A', 0, 7, 0]);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        assert!(report.accelerators.is_empty());
        assert!(
            report
                .limitations
                .iter()
                .any(|issue| issue.contains("RT_ACCELERATOR resource 0 is malformed"))
        );
    }

    #[test]
    fn decodes_cursor_group_hotspots_and_missing_reference() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 12);
        write_u32(&mut bytes, 0x400 + 72 + 4, 20);
        write_u16(&mut bytes, 0x458, 0);
        write_u16(&mut bytes, 0x45a, 2);
        write_u16(&mut bytes, 0x45c, 1);
        bytes[0x45e] = 32;
        bytes[0x45f] = 32;
        write_u16(&mut bytes, 0x462, 4);
        write_u16(&mut bytes, 0x464, 8);
        write_u32(&mut bytes, 0x466, 256);
        write_u16(&mut bytes, 0x46a, 7);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        let image = &report.cursor_groups[0].images[0];
        assert_eq!(image.hotspot_x, 4);
        assert_eq!(image.hotspot_y, 8);
        assert_eq!(image.declared_bytes, 256);
        assert!(matches!(image.reference, super::IconReference::Missing));
        assert_eq!(image.location.offset, 0x45e);
    }

    #[test]
    fn rejects_malformed_cursor_group_without_partial_projection() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 12);
        write_u32(&mut bytes, 0x400 + 72 + 4, 7);
        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap_err();
        assert!(matches!(
            report,
            Error::Malformed("RT_GROUP_CURSOR length does not match its image count")
        ));
    }

    #[test]
    fn decodes_bitmap_dib_metadata_without_pixels() {
        let mut bytes = fixture(false);
        let mut payload = vec![0u8; 40];
        payload[0..4].copy_from_slice(&40u32.to_le_bytes());
        payload[4..8].copy_from_slice(&64i32.to_le_bytes());
        payload[8..12].copy_from_slice(&(-32i32).to_le_bytes());
        payload[12..14].copy_from_slice(&1u16.to_le_bytes());
        payload[14..16].copy_from_slice(&32u16.to_le_bytes());
        payload[20..24].copy_from_slice(&8192u32.to_le_bytes());
        write_u32(&mut bytes, 0x400 + 16, 2);
        write_u32(&mut bytes, 0x400 + 72 + 4, payload.len() as u32);
        bytes[0x458..0x458 + payload.len()].copy_from_slice(&payload);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        let bitmap = &report.bitmaps[0];
        assert_eq!(bitmap.layout, "resource_dib");
        assert_eq!(bitmap.width, 64);
        assert_eq!(bitmap.height, -32);
        assert_eq!(bitmap.planes, 1);
        assert_eq!(bitmap.bit_count, 32);
        assert_eq!(bitmap.declared_image_bytes, 8192);
        assert_eq!(bitmap.header_location.bytes, 40);
    }

    #[test]
    fn reports_truncated_bitmap_header_without_partial_metadata() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 2);
        write_u32(&mut bytes, 0x400 + 72 + 4, 8);
        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        assert!(report.bitmaps.is_empty());
        assert!(
            report
                .limitations
                .iter()
                .any(|issue| issue.contains("RT_BITMAP resource 0 is malformed"))
        );
    }

    #[test]
    fn decodes_fontdir_count_and_associated_ids() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 7);
        write_u32(&mut bytes, 0x400 + 72 + 4, 6);
        bytes[0x458..0x45e].copy_from_slice(&[2, 0, 7, 0, 8, 0]);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        let font = &report.fonts[0];
        assert_eq!(font.kind, "fontdir");
        assert_eq!(font.declared_entry_count, Some(2));
        assert_eq!(font.associated_resource_ids, vec![7, 8]);
        assert_eq!(font.header_location.offset, 0x458);
        assert_eq!(
            font.entry_locations,
            vec![
                super::Range {
                    offset: 0x45a,
                    bytes: 2,
                },
                super::Range {
                    offset: 0x45c,
                    bytes: 2,
                },
            ]
        );
    }

    #[test]
    fn rejects_truncated_fontdir_without_partial_metadata() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 7);
        write_u32(&mut bytes, 0x400 + 72 + 4, 3);
        bytes[0x458..0x45b].copy_from_slice(&[2, 0, 7]);
        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        assert!(report.fonts.is_empty());
        assert!(
            report
                .limitations
                .iter()
                .any(|issue| issue.contains("RT_FONTDIR resource 0 is malformed"))
        );
    }

    #[test]
    fn extracts_html_bytes_with_identity_and_source_range() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 23);
        bytes[0x458..0x45d].copy_from_slice(b"<h1/>");
        write_u32(&mut bytes, 0x400 + 72 + 4, 6);

        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        let html = &report.html[0];
        assert_eq!(html.r#type, Identity::Id { id: 23 });
        assert_eq!(html.name, Identity::Id { id: 7 });
        assert_eq!(html.language, Identity::Id { id: 1033 });
        assert_eq!(html.code_page, 65001);
        assert_eq!(html.location.offset, 0x458);
        assert_eq!(html.raw_bytes, b"<h1/>");
    }

    #[test]
    fn reports_empty_html_without_partial_projection() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 23);
        write_u32(&mut bytes, 0x400 + 72 + 4, 0);
        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        assert!(report.html.is_empty());
        assert!(
            report
                .limitations
                .iter()
                .any(|issue| issue.contains("RT_HTML resource 0 has an empty payload"))
        );
    }

    #[test]
    fn extracts_rcdata_bytes_with_identity_and_range() {
        let bytes = fixture(false);
        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        let data = &report.rcdata[0];
        assert_eq!(data.r#type, Identity::Id { id: 10 });
        assert_eq!(data.name, Identity::Id { id: 7 });
        assert_eq!(data.language, Identity::Id { id: 1033 });
        assert_eq!(data.code_page, 65001);
        assert_eq!(data.location.offset, 0x458);
        assert_eq!(data.raw_bytes, b"ICON");
    }

    #[test]
    fn decodes_icon_dib_header_and_retains_raw_bytes() {
        let mut bytes = fixture(false);
        let mut payload = vec![0u8; 40];
        payload[0..4].copy_from_slice(&40u32.to_le_bytes());
        payload[4..8].copy_from_slice(&16i32.to_le_bytes());
        payload[8..12].copy_from_slice(&32i32.to_le_bytes());
        payload[12..14].copy_from_slice(&1u16.to_le_bytes());
        payload[14..16].copy_from_slice(&32u16.to_le_bytes());
        write_u32(&mut bytes, 0x400 + 16, 3);
        write_u32(&mut bytes, 0x400 + 72 + 4, payload.len() as u32);
        bytes[0x458..0x458 + payload.len()].copy_from_slice(&payload);
        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        let icon = &report.icons[0];
        assert_eq!(icon.resource_id, Identity::Id { id: 7 });
        assert_eq!(icon.format, "dib");
        assert_eq!(icon.width, Some(16));
        assert_eq!(icon.height, Some(16));
        assert_eq!(icon.bit_count, Some(32));
        assert_eq!(icon.raw_bytes.len(), 40);
    }

    #[test]
    fn reports_truncated_icon_header_without_partial_image_facts() {
        let mut bytes = fixture(false);
        write_u32(&mut bytes, 0x400 + 16, 3);
        write_u32(&mut bytes, 0x400 + 72 + 4, 4);
        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        assert!(report.icons.is_empty());
        assert!(report.limitations.iter().any(|issue| {
            issue.contains("RT_ICON resource 0 is empty or exceeds")
                || issue.contains("RT_ICON resource 0 has malformed")
        }));
    }

    #[test]
    fn decodes_cursor_dib_metadata_separately_from_icons() {
        let mut bytes = fixture(false);
        let mut payload = vec![0u8; 40];
        payload[0..4].copy_from_slice(&40u32.to_le_bytes());
        payload[4..8].copy_from_slice(&16i32.to_le_bytes());
        payload[8..12].copy_from_slice(&32i32.to_le_bytes());
        payload[12..14].copy_from_slice(&1u16.to_le_bytes());
        payload[14..16].copy_from_slice(&32u16.to_le_bytes());
        write_u32(&mut bytes, 0x400 + 16, 1);
        write_u32(&mut bytes, 0x400 + 72 + 4, payload.len() as u32);
        bytes[0x458..0x458 + payload.len()].copy_from_slice(&payload);
        let report = read(
            &bytes,
            artifact(&bytes),
            input(MAX_DIRECTORY_ENTRIES),
            &Cancellation::default(),
        )
        .unwrap();
        let cursor = &report.cursors[0];
        assert_eq!(cursor.resource_id, Identity::Id { id: 7 });
        assert_eq!(cursor.format, "dib");
        assert_eq!(cursor.width, Some(16));
        assert_eq!(cursor.height, Some(16));
        assert_eq!(cursor.hotspot_x, None);
        assert_eq!(cursor.raw_bytes.len(), 40);
        assert!(report.icons.is_empty());
    }

    #[test]
    fn rejects_entry_budget_without_returning_partial_inventory() {
        let bytes = fixture(false);
        let error = read(&bytes, artifact(&bytes), input(2), &Cancellation::default()).unwrap_err();

        assert!(matches!(
            error,
            Error::ResourceLimit {
                boundary: "capacity",
                maximum: 2,
                reason: "PE resource directory entry budget exceeded; no partial inventory was returned.",
            }
        ));
    }

    #[test]
    fn cancellation_is_checked_before_parsing() {
        let bytes = fixture(false);
        let cancellation = Cancellation::default();
        cancellation.cancel("test cancellation");

        assert!(matches!(
            read(&bytes, artifact(&bytes), input(8), &cancellation),
            Err(Error::Cancelled(reason)) if reason == "test cancellation"
        ));
    }

    #[test]
    fn absent_directory_is_distinct_from_a_present_empty_directory() {
        let mut bytes = fixture(false);
        let resource_directory = 0x98 + 112;
        write_u32(&mut bytes, resource_directory, 0);
        write_u32(&mut bytes, resource_directory + 4, 0);
        let absent = read(&bytes, artifact(&bytes), input(8), &Cancellation::default()).unwrap();
        assert!(absent.directory.is_none());
        assert!(absent.resources.is_empty());

        write_u32(&mut bytes, resource_directory, 0x2000);
        write_u32(&mut bytes, resource_directory + 4, 16);
        bytes[0x400..0x400 + 92].fill(0);
        let empty = read(&bytes, artifact(&bytes), input(8), &Cancellation::default()).unwrap();
        assert!(empty.directory.is_some());
        assert!(empty.resources.is_empty());
    }

    fn version_block(key: &str, value_type: u16, value: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
        let key_bytes = key
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0, 0])
            .collect::<Vec<_>>();
        let mut body = vec![0; 6];
        body.extend(key_bytes);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        body.extend(value);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        for child in children {
            body.extend(child);
        }
        let length = u16::try_from(body.len()).unwrap();
        body[0..2].copy_from_slice(&length.to_le_bytes());
        body[2..4].copy_from_slice(
            &u16::try_from(if value_type == 1 {
                value.len() / 2
            } else {
                value.len()
            })
            .unwrap()
            .to_le_bytes(),
        );
        body[4..6].copy_from_slice(&value_type.to_le_bytes());
        body
    }

    #[test]
    fn decodes_bounded_version_blocks_and_preserves_string_ranges() {
        let mut fixed = vec![0u8; 52];
        fixed[0..4].copy_from_slice(&0xfeef04bdu32.to_le_bytes());
        fixed[8..12].copy_from_slice(&1u32.to_le_bytes());
        fixed[12..16].copy_from_slice(&2u32.to_le_bytes());
        fixed[16..20].copy_from_slice(&3u32.to_le_bytes());
        fixed[20..24].copy_from_slice(&4u32.to_le_bytes());
        let text = "Acme"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0, 0])
            .collect::<Vec<_>>();
        let leaf = version_block("CompanyName", 1, &text, &[]);
        let table = version_block("040904b0", 0, &[], &[leaf]);
        let strings = version_block("StringFileInfo", 0, &[], &[table]);
        let root = version_block("VS_VERSION_INFO", 0, &fixed, &[strings]);

        let parsed = super::parse_version_payload(&root, 100).unwrap();
        assert_eq!(parsed.file_version.as_deref(), Some("0.1.0.2"));
        assert_eq!(parsed.product_version.as_deref(), Some("0.3.0.4"));
        assert_eq!(
            parsed.strings.get("CompanyName").map(String::as_str),
            Some("Acme")
        );
        assert_eq!(
            parsed.string_locations["CompanyName"].offset,
            100 + root.windows(2).position(|pair| pair == [b'A', 0]).unwrap()
        );
    }

    #[test]
    fn rejects_version_block_with_child_extent_outside_parent() {
        let mut root = version_block("VS_VERSION_INFO", 0, &[], &[]);
        let malformed_length = u16::try_from(root.len() - 2).unwrap();
        root[0..2].copy_from_slice(&malformed_length.to_le_bytes());
        assert!(super::parse_version_payload(&root, 0).is_err());
    }

    #[test]
    fn rejects_resource_range_end_overflow_before_overlap_comparison() {
        let mut ranges = vec![super::OccupiedRange {
            range: super::Range {
                offset: usize::MAX - 1,
                bytes: 4,
            },
            kind: super::RangeKind::Payload,
        }];
        let error = super::reject_overlapping_ranges(&mut ranges).unwrap_err();
        assert!(matches!(
            error,
            Error::Malformed("resource byte range overflows")
        ));
    }

    #[test]
    fn rejects_icon_image_source_offset_overflow() {
        assert_eq!(super::icon_image_offset(usize::MAX - 4, 0), None);
        assert_eq!(super::icon_image_offset(0, usize::MAX), None);
    }
}
