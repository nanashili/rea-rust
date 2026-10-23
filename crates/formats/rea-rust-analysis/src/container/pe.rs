use super::{Container, Error, Format, ImageLayout, Mapping, Reader, Sections, ZeroFill};

#[derive(Clone)]
pub(crate) struct ResourceLayout {
    pub format: PeFormat,
    pub machine: u32,
    pub directory_at: usize,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub header_size: usize,
    pub sections: Vec<ResourceSection>,
}

#[derive(Clone, Copy)]
pub(crate) enum PeFormat {
    Pe32,
    Pe32Plus,
}

/// Admit the PE layout used to map the resource directory and payload RVAs.
pub(crate) fn read_resource_layout(bytes: &[u8]) -> Result<ResourceLayout, Error> {
    let reader = Reader {
        bytes,
        little: true,
    };
    reader.range(0, 64)?;
    if reader.u16(0)? != 0x5a4d {
        return Err(Error::Malformed("expected an MZ PE image"));
    }

    let pe = usize::try_from(reader.u32(60)?)
        .map_err(|_| Error::Malformed("PE header offset exceeds host limits"))?;
    reader.range(pe as u64, 24)?;
    if reader.u32(pe)? != 0x0000_4550 {
        return Err(Error::Malformed("expected a PE signature"));
    }

    let section_count = usize::from(reader.u16(pe + 6)?);
    let optional_size = usize::from(reader.u16(pe + 20)?);
    let optional = pe + 24;
    reader.range(optional as u64, optional_size as u64)?;
    if optional_size < 64 {
        return Err(Error::Malformed("truncated PE optional header"));
    }

    let format = match reader.u16(optional)? {
        0x10b => PeFormat::Pe32,
        0x20b => PeFormat::Pe32Plus,
        _ => return Err(Error::Unsupported("unsupported PE optional header magic")),
    };
    let count_at = if matches!(format, PeFormat::Pe32) {
        92
    } else {
        108
    };
    let directories_at = count_at + 4;
    if optional_size < directories_at {
        return Err(Error::Malformed("truncated PE data directory count"));
    }

    let directory_count = reader.u32(optional + count_at)? as usize;
    if directory_count > (optional_size - directories_at) / 8 {
        return Err(Error::Malformed(
            "PE directory count exceeds its optional header",
        ));
    }

    let header_size = usize::try_from(reader.u32(optional + 60)?)
        .map_err(|_| Error::Malformed("PE SizeOfHeaders exceeds host limits"))?;
    let sections_at = optional + optional_size;
    let section_table_size = section_count
        .checked_mul(40)
        .ok_or(Error::Malformed("PE section table size overflows"))?;
    let section_table_end = sections_at
        .checked_add(section_table_size)
        .ok_or(Error::Malformed("PE section table end overflows"))?;
    reader.range(sections_at as u64, section_table_size as u64)?;
    if header_size < section_table_end || header_size > bytes.len() {
        return Err(Error::Malformed("invalid PE SizeOfHeaders"));
    }

    let mut raw_ranges = Vec::new();
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let section = sections_at + index * 40;
        let virtual_size = reader.u32(section + 8)?;
        let virtual_address = reader.u32(section + 12)?;
        let raw_size = reader.u32(section + 16)?;
        let raw_offset = reader.u32(section + 20)?;
        let virtual_extent = if virtual_size == 0 {
            raw_size
        } else {
            virtual_size
        };
        if u64::from(virtual_address) + u64::from(virtual_extent) > 0x1_0000_0000 {
            return Err(Error::Malformed("PE section RVA range overflows"));
        }
        sections.push(ResourceSection {
            index,
            rva: u64::from(virtual_address),
            virtual_extent: u64::from(virtual_extent),
            raw_offset,
            raw_size,
        });
        if raw_size > 0 {
            let raw_range = reader.range(u64::from(raw_offset), u64::from(raw_size))?;
            if raw_range.start < header_size {
                return Err(Error::Malformed("PE section raw bytes overlap headers"));
            }
            raw_ranges.push(raw_range);
        }
    }

    raw_ranges.sort_unstable_by_key(|range| range.start);
    for pair in raw_ranges.windows(2) {
        if pair[1].start < pair[0].end {
            return Err(Error::Malformed(
                "PE sections have overlapping raw file ranges",
            ));
        }
    }

    let directory_at = optional + directories_at + 16;
    let (directory_rva, directory_size) = if directory_count > 2 {
        (reader.u32(directory_at)?, reader.u32(directory_at + 4)?)
    } else {
        (0, 0)
    };
    if (directory_rva == 0) != (directory_size == 0) {
        return Err(Error::Malformed(
            "inconsistent PE resource directory RVA/size",
        ));
    }

    Ok(ResourceLayout {
        format,
        machine: u32::from(reader.u16(pe + 4)?),
        directory_at,
        directory_rva,
        directory_size,
        header_size,
        sections,
    })
}

impl ResourceLayout {
    /// Map one resource RVA interval only when its file ownership is unique.
    pub(crate) fn map_rva(&self, bytes: &[u8], rva: u32, size: u32) -> Result<usize, Error> {
        let start = u64::from(rva);
        let length = u64::from(size);
        start
            .checked_add(length)
            .filter(|end| *end <= 0x1_0000_0000)
            .ok_or(Error::Malformed("resource RVA range overflows"))?;
        let reader = Reader {
            bytes,
            little: true,
        };

        let containing: Vec<_> = self
            .sections
            .iter()
            .filter(|section| start >= section.rva && start - section.rva < section.virtual_extent)
            .collect();
        let candidates: Vec<_> = if size == 0 && containing.is_empty() {
            self.sections
                .iter()
                .filter(|section| {
                    section.virtual_extent > 0
                        && start >= section.rva
                        && start - section.rva == section.virtual_extent
                })
                .collect()
        } else {
            containing
        };

        if start < self.header_size as u64 {
            if self
                .sections
                .iter()
                .any(|section| intersects_resource(section, start, length))
                || length > self.header_size as u64 - start
            {
                return Err(Error::Malformed("ambiguous resource header RVA mapping"));
            }
            reader.range(start, length)?;
            return usize::try_from(start)
                .map_err(|_| Error::Malformed("resource file offset exceeds host limits"));
        }

        if candidates.len() != 1 {
            return Err(Error::Malformed(
                "resource RVA has missing or overlapping section mappings",
            ));
        }
        let section = candidates[0];
        let within = start - section.rva;
        if length > section.virtual_extent - within {
            return Err(Error::Malformed(
                "resource range leaves its section virtual size",
            ));
        }
        if within > u64::from(section.raw_size) || length > u64::from(section.raw_size) - within {
            return Err(Error::Malformed(
                "resource range is not entirely file-backed in one section",
            ));
        }
        if self
            .sections
            .iter()
            .any(|other| other.index != section.index && intersects_resource(other, start, length))
        {
            return Err(Error::Malformed(
                "resource interval intersects overlapping virtual sections",
            ));
        }

        let offset = u64::from(section.raw_offset) + within;
        reader.range(offset, length)?;
        usize::try_from(offset)
            .map_err(|_| Error::Malformed("resource file offset exceeds host limits"))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ResourceSection {
    pub index: usize,
    pub rva: u64,
    pub virtual_extent: u64,
    pub raw_offset: u32,
    pub raw_size: u32,
}

fn intersects_resource(section: &ResourceSection, rva: u64, size: u64) -> bool {
    let Some(resource_end) = rva.checked_add(size.max(1)) else {
        return false;
    };
    let Some(section_end) = section.rva.checked_add(section.virtual_extent) else {
        return false;
    };

    section.virtual_extent > 0 && section.rva < resource_end && rva < section_end
}

pub(super) fn read(bytes: &[u8]) -> Result<Container, Error> {
    let r = Reader {
        bytes,
        little: true,
    };
    let pe = windows_header(&r)?;
    let optional = pe + 24;
    let optional_size = usize::from(r.u16(pe + 20)?);
    r.range(optional as u64, optional_size as u64)?;
    if optional_size < 2 {
        return Err(Error::Malformed("PE optional header magic is truncated"));
    }
    let bits = match r.u16(optional)? {
        0x10b => 32,
        0x20b => 64,
        _ => {
            return Err(Error::Unsupported(
                "only PE32 and PE32+ optional headers are supported",
            ));
        }
    };
    let directories = if bits == 64 { 112 } else { 96 };
    if optional_size < directories {
        return Err(Error::Malformed("PE optional header is truncated"));
    }
    if u64::from(r.u32(optional + directories - 4)?) * 8 > (optional_size - directories) as u64 {
        return Err(Error::Malformed(
            "PE data directories exceed the optional header",
        ));
    }
    let base = r.word(optional + if bits == 64 { 24 } else { 28 }, bits)?;
    let count = usize::from(r.u16(pe + 6)?);
    let start = r.table((optional + optional_size) as u64, count as u64, 40)?;
    let mut sections = Sections::default();
    let mut mappings = Vec::new();
    let mut zero_fills = Vec::new();
    let mut search = None;
    for index in 0..count {
        let entry = start + index * 40;
        let name = r.fixed_name(entry, 8)?;
        let virtual_size = r.u32(entry + 8)?;
        let virtual_address = r.u32(entry + 12)?;
        let size = r.u32(entry + 16)?;
        let offset = r.u32(entry + 20)?;
        let flags = r.u32(entry + 36)?;
        if u128::from(base) + u128::from(virtual_address) + u128::from(size.max(virtual_size))
            > 1_u128 << bits
        {
            return Err(Error::Malformed(
                "PE section virtual address exceeds its address width",
            ));
        }
        let address = u64::try_from(u128::from(base) + u128::from(virtual_address))
            .map_err(|_| Error::Malformed("PE section virtual address exceeds its width"))?;
        let mapping = if size == 0 {
            None
        } else {
            Some(Mapping {
                address,
                span: r.range(u64::from(offset), u64::from(size))?,
            })
        };
        if let Some(mapping) = mapping.as_ref() {
            mappings.push(mapping.clone());
        }
        if virtual_size > size {
            zero_fills.push(ZeroFill {
                address: u128::from(address) + u128::from(size),
                size: u128::from(virtual_size - size),
            });
        }
        if search.is_none()
            && virtual_address != 0
            && size != 0
            && flags & !0x0060_0000 == 0xc000_0040
        {
            let mapping = mapping
                .as_ref()
                .ok_or(Error::Malformed("PE build-info section is not file-backed"))?;
            let search_size = usize::try_from(size.min(virtual_size))
                .map_err(|_| Error::Malformed("PE build-info range exceeds host limits"))?;
            search = Some(Mapping {
                address,
                span: mapping.span.start..mapping.span.start + search_size,
            });
        }
        if name.is_empty() {
            continue;
        }
        // VirtualSize excludes SizeOfRawData's alignment padding.
        let content_size = if virtual_size == 0 {
            size
        } else {
            virtual_size.min(size)
        };
        let span = r.declared(u64::from(offset), u64::from(content_size));
        let read_only = span.is_some()
            && flags & 0x4000_0000 != 0
            && flags & 0xa000_0000 == 0
            && flags & 0x40 != 0;
        sections.observe(span, name == b".dep-v0", read_only, false);
    }
    let machine = r.u16(pe + 4)?;
    let architecture = match machine {
        0x14c => "386".into(),
        0x8664 => "amd64".into(),
        0x1c0 | 0x1c2 | 0x1c4 => "arm".into(),
        0xaa64 => "arm64".into(),
        _ => format!("pe-machine-{machine}"),
    };
    sections.finish(ImageLayout {
        format: Format::Pe,
        architecture,
        bits,
        little_endian: true,
        mappings,
        zero_fills,
        build_info_search: search.into_iter().collect(),
    })
}

fn windows_header(r: &Reader<'_>) -> Result<usize, Error> {
    let mut declared = None;
    if r.bytes.len() >= 64 {
        let header = u32::from(r.u16(8)?) * 16;
        let relocations = u32::from(r.u16(6)?);
        let table = u32::from(r.u16(24)?);
        let relocation_overlaps_pointer =
            header != 0 && relocations > 0 && table < 64 && table + relocations * 4 > 60;
        if !relocation_overlaps_pointer {
            let offset = r.u32(60)? as usize;
            if offset != 0 {
                let signature = r.bytes.get(offset..).unwrap_or_default();
                if header == 0
                    || header >= 64
                    || signature.starts_with(b"PE\0\0")
                    || signature.starts_with(b"NE")
                    || signature.starts_with(b"LE")
                    || signature.starts_with(b"LX")
                {
                    declared = Some(offset);
                }
            }
        }
    }
    let Some(offset) = declared else {
        validate_dos(r)?;
        return Err(Error::Unsupported("DOS-only images are not supported"));
    };
    if offset < 64 {
        return Err(Error::Malformed("PE signature overlaps the DOS header"));
    }
    r.range(offset as u64, 24)?;
    let signature = &r.bytes[offset..offset + 4];
    if signature.starts_with(b"NE") || signature.starts_with(b"LE") || signature.starts_with(b"LX")
    {
        return Err(Error::Unsupported("NE/LE/LX images are not supported"));
    }
    if signature != b"PE\0\0" {
        return Err(Error::Malformed("invalid PE signature"));
    }
    Ok(offset)
}

fn validate_dos(r: &Reader<'_>) -> Result<(), Error> {
    r.range(0, 28)?;
    let last = u32::from(r.u16(2)?);
    let pages = u32::from(r.u16(4)?);
    if pages == 0 || last > 511 {
        return Err(Error::Malformed(
            "invalid DOS MZ page count or final-page size",
        ));
    }
    let image = (pages - 1) * 512 + if last == 0 { 512 } else { last };
    let header = u32::from(r.u16(8)?) * 16;
    if header < 28 || header >= image {
        return Err(Error::Malformed(
            "invalid DOS MZ header or empty load module",
        ));
    }
    if image as usize > r.bytes.len() {
        return Err(Error::Malformed("truncated DOS MZ load module"));
    }
    let count = u32::from(r.u16(6)?);
    let table = u32::from(r.u16(24)?);
    if count > 0 && (table < 28 || table + count * 4 > header) {
        return Err(Error::Malformed(
            "DOS MZ relocation table lies outside its header",
        ));
    }
    let module_size = image - header;
    for index in 0..count {
        let offset = (table + index * 4) as usize;
        if u32::from(r.u16(offset + 2)?) * 16 + u32::from(r.u16(offset)?) + 2 > module_size {
            return Err(Error::Malformed(
                "DOS MZ relocation points outside its load module",
            ));
        }
    }
    if u32::from(r.u16(22)?) * 16 + u32::from(r.u16(20)?) >= module_size {
        return Err(Error::Malformed(
            "DOS MZ entry point lies outside its load module",
        ));
    }
    Ok(())
}
