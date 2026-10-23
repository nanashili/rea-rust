use super::{
    Container, Error, Format, ImageLayout, Mapping, Reader, Sections, ZeroFill, mapped_offset,
};

pub(super) fn read(bytes: &[u8]) -> Result<Container, Error> {
    if bytes.len() < 16 {
        return Err(Error::Malformed("ELF identification is truncated"));
    }
    let bits = match bytes[4] {
        1 => 32,
        2 => 64,
        _ => return Err(Error::Malformed("unsupported ELF class")),
    };
    let little = match bytes[5] {
        1 => true,
        2 => false,
        _ => return Err(Error::Malformed("unsupported ELF endianness")),
    };
    if bytes[6] != 1 {
        return Err(Error::Malformed("unsupported ELF identification version"));
    }
    let r = Reader { bytes, little };
    let wide = bits == 64;
    let minimum = if wide { 64 } else { 52 };
    r.range(0, minimum)?;
    if r.u32(20)? != 1 {
        return Err(Error::Malformed("unsupported ELF header version"));
    }
    let header = u64::from(r.u16(if wide { 52 } else { 40 })?);
    if header < minimum || header > bytes.len() as u64 {
        return Err(Error::Malformed("invalid ELF header size"));
    }
    let ph_offset = r.word(if wide { 32 } else { 28 }, bits)?;
    let sh_offset = r.word(if wide { 40 } else { 32 }, bits)?;
    let ph_width = u64::from(r.u16(if wide { 54 } else { 42 })?);
    let sh_width = u64::from(r.u16(if wide { 58 } else { 46 })?);
    let mut ph_count = u64::from(r.u16(if wide { 56 } else { 44 })?);
    let mut sh_count = u64::from(r.u16(if wide { 60 } else { 48 })?);
    let mut names_index = u64::from(r.u16(if wide { 62 } else { 50 })?);
    if (ph_count != 0 && ph_offset < header) || (sh_offset != 0 && sh_offset < header) {
        return Err(Error::Malformed("ELF table overlaps native header"));
    }
    if sh_offset != 0 && (sh_count == 0 || ph_count == 0xffff || names_index == 0xffff) {
        if sh_width < if wide { 64 } else { 40 } {
            return Err(Error::Malformed("invalid extended ELF section width"));
        }
        let first = r.range(sh_offset, sh_width)?.start;
        if r.u32(first + 4)? != 0 {
            return Err(Error::Malformed(
                "extended ELF section zero must have SHT_NULL type",
            ));
        }
        if sh_count == 0 {
            sh_count = r.word(first + if wide { 32 } else { 20 }, bits)?;
            if !(0xff00..=9_007_199_254_740_991).contains(&sh_count) {
                return Err(Error::Malformed("invalid extended ELF section count"));
            }
        }
        if ph_count == 0xffff {
            ph_count = u64::from(r.u32(first + if wide { 44 } else { 28 })?);
            if ph_count < 0xffff {
                return Err(Error::Malformed(
                    "extended ELF program count below reserved range",
                ));
            }
        }
        if names_index == 0xffff {
            names_index = u64::from(r.u32(first + if wide { 40 } else { 24 })?);
            if names_index < 0xff00 {
                return Err(Error::Malformed(
                    "extended ELF name index below reserved range",
                ));
            }
        }
    } else if sh_offset == 0 && (sh_count != 0 || names_index != 0 || ph_count == 0xffff) {
        return Err(Error::Malformed("ELF section table is missing"));
    }
    if ph_count != 0 && ph_width < if wide { 56 } else { 32 } {
        return Err(Error::Malformed("invalid ELF program width"));
    }
    let ph_start = r.table(ph_offset, ph_count, ph_width)?;
    let mut mappings = Vec::new();
    let mut zeros = Vec::new();
    let mut fallback_search = Vec::new();
    for index in 0..ph_count as usize {
        let entry = ph_start + index * ph_width as usize;
        if r.u32(entry)? != 1 {
            continue;
        }
        let flags = r.u32(entry + if wide { 4 } else { 24 })?;
        let offset = r.word(entry + if wide { 8 } else { 4 }, bits)?;
        let address = r.word(entry + if wide { 16 } else { 8 }, bits)?;
        let size = r.word(entry + if wide { 32 } else { 16 }, bits)?;
        let memory = r.word(entry + if wide { 40 } else { 20 }, bits)?;
        if size > memory || u128::from(address) + u128::from(memory) > 1_u128 << bits {
            return Err(Error::Malformed("invalid ELF load segment address or size"));
        }
        let mapping = if size != 0 {
            Some(Mapping {
                address,
                span: r.range(offset, size)?,
            })
        } else {
            None
        };
        if let Some(mapping) = mapping {
            if flags & 3 == 2 {
                fallback_search.push(mapping.clone());
            }
            mappings.push(mapping);
        }
        if memory > size {
            zeros.push(ZeroFill {
                address: u128::from(address) + u128::from(size),
                size: u128::from(memory - size),
            });
        }
    }
    let mut sections = Sections::default();
    let mut build_info_count = 0;
    let mut named_search = None;
    if sh_count != 0 {
        if sh_width < if wide { 64 } else { 40 } || names_index >= sh_count {
            return Err(Error::Malformed("invalid ELF section width or name index"));
        }
        let sh_start = r.table(sh_offset, sh_count, sh_width)?;
        if names_index != 0 {
            let name_header = sh_start + names_index as usize * sh_width as usize;
            if r.u32(name_header + 4)? != 3 {
                return Err(Error::Malformed("ELF section names are not a string table"));
            }
            let names = r.range(
                r.word(name_header + if wide { 24 } else { 16 }, bits)?,
                r.word(name_header + if wide { 32 } else { 20 }, bits)?,
            )?;
            for index in 0..sh_count as usize {
                let entry = sh_start + index * sh_width as usize;
                let name_offset = r.u32(entry)? as usize;
                if name_offset >= names.len() {
                    return Err(Error::Malformed(
                        "ELF section name offset exceeds string table",
                    ));
                }
                let start = names.start + name_offset;
                let window = &bytes[start..(start + 64).min(names.end)];
                let nul = window.iter().position(|byte| *byte == 0);
                let name = nul.map(|end| &window[..end]);
                let kind = r.u32(entry + 4)?;
                let flags = r.word(entry + 8, bits)?;
                let offset = r.word(entry + if wide { 24 } else { 16 }, bits)?;
                let size = r.word(entry + if wide { 32 } else { 20 }, bits)?;
                let compressed = flags & 0x800 != 0;
                let span = if kind == 8 {
                    None
                } else {
                    r.declared(offset, size)
                };
                let read_only = kind == 1
                    && span.is_some()
                    && !compressed
                    && flags & 1 == 0
                    && flags & 4 == 0
                    && flags & 2 != 0;
                // Unnamed sections are omitted by the compatibility owner;
                // overlong names still retain read-only compiler-path coverage.
                if name.is_some_and(|name| !name.is_empty()) || (name.is_none() && read_only) {
                    sections.observe(span, name == Some(&b".dep-v0"[..]), read_only, compressed);
                }
                if name == Some(&b".go.buildinfo"[..]) {
                    build_info_count += 1;
                    if build_info_count > 1 {
                        return Err(Error::Malformed(
                            "ELF contains ambiguous build-info sections",
                        ));
                    }
                    if kind != 1 {
                        return Err(Error::Malformed(
                            "ELF build-info section is not file-backed data",
                        ));
                    }
                    if compressed {
                        return Err(Error::Unsupported(
                            "compressed ELF build-info sections are unsupported",
                        ));
                    }
                    let address = r.word(entry + if wide { 16 } else { 12 }, bits)?;
                    let info = r.range(offset, size)?;
                    if mapped_offset(&mappings, &zeros, address, info.len())? != info.start {
                        return Err(Error::Malformed(
                            "ELF build-info section disagrees with its mapping",
                        ));
                    }
                    named_search = Some(Mapping {
                        address,
                        span: info,
                    });
                }
            }
        }
    }
    let machine = r.u16(18)?;
    let architecture = match machine {
        3 => "386".into(),
        8 => "mips".into(),
        20 => "ppc".into(),
        21 => "ppc64".into(),
        22 => "s390".into(),
        40 => "arm".into(),
        62 => "amd64".into(),
        183 => "arm64".into(),
        243 => "riscv".into(),
        258 => "loongarch".into(),
        _ => format!("elf-machine-{machine}"),
    };
    let build_info_search = named_search.map_or(fallback_search, |mapping| vec![mapping]);
    sections.finish(ImageLayout {
        format: Format::Elf,
        architecture,
        bits,
        little_endian: little,
        mappings,
        zero_fills: zeros,
        build_info_search,
    })
}
