use super::{
    Container, Error, Format, ImageLayout, Mapping, Reader, Sections, ZeroFill, mapped_offset,
};

pub(super) fn read(bytes: &[u8], magic: u32) -> Result<Container, Error> {
    let little = matches!(magic, 0xcefaedfe | 0xcffaedfe);
    let bits = if matches!(magic, 0xfeedfacf | 0xcffaedfe) {
        64
    } else {
        32
    };
    let r = Reader { bytes, little };
    let header_size = if bits == 64 { 32 } else { 28 };
    r.range(0, header_size)?;
    let count = r.u32(16)? as usize;
    let command_bytes = r.u32(20)? as usize;
    let start = r.table(header_size, command_bytes as u64, 1)?;
    if count > command_bytes / 8 {
        return Err(Error::Malformed(
            "Mach-O command count exceeds command bytes",
        ));
    }
    let end = start + command_bytes;
    let mut offset = start;
    let mut sections = Sections::default();
    let mut mappings = Vec::new();
    let mut zero_fills = Vec::new();
    let mut fallback_search = None;
    let mut named_search = None;
    let mut build_info_count = 0;
    for _ in 0..count {
        let command = r.u32(offset)?;
        let size = r.u32(offset + 4)? as usize;
        if size < 8 || !size.is_multiple_of(4) || size > end - offset {
            return Err(Error::Malformed("invalid or truncated Mach-O load command"));
        }
        if command == 1 || command == 0x19 {
            let wide = command == 0x19;
            if wide != (bits == 64) {
                return Err(Error::Malformed(
                    "Mach-O segment width disagrees with header",
                ));
            }
            let segment_header = if wide { 72 } else { 56 };
            let section_width = if wide { 80 } else { 68 };
            if size < segment_header {
                return Err(Error::Malformed("truncated Mach-O segment header"));
            }
            let address = r.word(offset + 24, bits)?;
            let memory_size = r.word(offset + if wide { 32 } else { 28 }, bits)?;
            let file_offset = r.word(offset + if wide { 40 } else { 32 }, bits)?;
            let file_size = r.word(offset + if wide { 48 } else { 36 }, bits)?;
            let max_protection = r.u32(offset + if wide { 56 } else { 40 })?;
            let protection = r.u32(offset + if wide { 60 } else { 44 })?;
            let section_count = r.u32(offset + if wide { 64 } else { 48 })? as usize;
            let segment_name = r.fixed_name(offset + 8, 16)?;
            let page_zero = segment_name == b"__PAGEZERO";
            let unmapped = memory_size == 0 && protection == 0;
            if (!unmapped && file_size > memory_size)
                || u128::from(address) + u128::from(memory_size) > 1_u128 << bits
            {
                return Err(Error::Malformed("invalid Mach-O segment address or size"));
            }
            if section_count > (size - segment_header) / section_width {
                return Err(Error::Malformed("Mach-O sections exceed segment command"));
            }
            if file_size > 0 {
                r.range(file_offset, file_size)?;
            }
            let mapping = if unmapped || file_size == 0 || page_zero {
                None
            } else {
                Some(Mapping {
                    address,
                    span: r.range(file_offset, file_size)?,
                })
            };
            if let Some(mapping) = mapping.as_ref() {
                mappings.push(mapping.clone());
                if fallback_search.is_none()
                    && address != 0
                    && protection == 3
                    && max_protection == 3
                {
                    fallback_search = Some(mapping.clone());
                }
            }
            if memory_size > file_size && !page_zero {
                zero_fills.push(ZeroFill {
                    address: u128::from(address) + u128::from(file_size),
                    size: u128::from(memory_size - file_size),
                });
            }
            for index in 0..section_count {
                let section = offset + segment_header + index * section_width;
                let name = r.fixed_name(section, 16)?;
                let segment_name = r.fixed_name(section + 16, 16)?;
                let flags = r.u32(section + if wide { 64 } else { 56 })?;
                let zero_fill = matches!(flags & 0xff, 1 | 0xc | 0x12);
                let section_address = r.word(section + 32, bits)?;
                let section_size = r.word(section + if wide { 40 } else { 36 }, bits)?;
                let section_offset = u64::from(r.u32(section + if wide { 48 } else { 40 })?);
                let in_memory = section_address.checked_sub(address).is_some_and(|delta| {
                    delta <= memory_size && section_size <= memory_size - delta
                });
                let in_file = section_offset
                    .checked_sub(file_offset)
                    .is_some_and(|delta| delta <= file_size && section_size <= file_size - delta);
                let span = if mapping.is_none() || zero_fill || !in_memory || !in_file {
                    None
                } else {
                    r.declared(section_offset, section_size)
                };
                let read_only = span.is_some()
                    && protection & 1 != 0
                    && protection & 2 == 0
                    && flags & 0x8000_0400 == 0;
                sections.observe(
                    span,
                    segment_name == b"__DATA" && name == b".dep-v0",
                    read_only,
                    false,
                );
                // Preserve the current shared container's validation even when
                // this inspection needs Rust metadata, not Go build information.
                if name == b"__go_buildinfo" {
                    build_info_count += 1;
                    let mapping = mapping
                        .as_ref()
                        .ok_or(Error::Malformed("Mach-O build-info section is not mapped"))?;
                    if zero_fill {
                        return Err(Error::Malformed("Mach-O build-info section is zero-fill"));
                    }
                    let info = r.range(section_offset, section_size)?;
                    if mapped_offset(
                        std::slice::from_ref(mapping),
                        &[],
                        section_address,
                        info.len(),
                    )? != info.start
                    {
                        return Err(Error::Malformed(
                            "Mach-O build-info section disagrees with its segment",
                        ));
                    }
                    named_search = Some(Mapping {
                        address: section_address,
                        span: info,
                    });
                }
            }
        }
        offset += size;
    }
    if offset != end {
        return Err(Error::Malformed(
            "Mach-O command bytes disagree with command count",
        ));
    }
    if build_info_count > 1 {
        return Err(Error::Malformed("Mach-O has ambiguous build-info sections"));
    }
    let cpu = r.u32(4)?;
    let architecture = match cpu {
        7 => "386".into(),
        0x0100_0007 => "amd64".into(),
        12 => "arm".into(),
        0x0100_000c => "arm64".into(),
        18 => "ppc".into(),
        0x0100_0012 => "ppc64".into(),
        _ => format!("macho-cpu-{cpu}"),
    };
    let build_info_search = named_search
        .map(|mapping| vec![mapping])
        .or_else(|| fallback_search.map(|mapping| vec![mapping]))
        .unwrap_or_default();
    sections.finish(ImageLayout {
        format: Format::Macho,
        architecture,
        bits,
        little_endian: little,
        mappings,
        zero_fills,
        build_info_search,
    })
}
