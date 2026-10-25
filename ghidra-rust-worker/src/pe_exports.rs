use std::ops::Range;
use std::str;

use anyhow::{Context, Result, ensure};
use object::File;
use object::read::ReadRef;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};

use crate::inventory::{MetadataFunction, admit_name, normalize};
use crate::protocol::MAX_INVENTORY;

pub fn function_symbols(
    file: &File<'_>,
    arm: bool,
    code_ranges: &[Range<u64>],
) -> Result<Vec<MetadataFunction>> {
    match file {
        File::Pe32(file) => parse(file, arm, code_ranges),
        File::Pe64(file) => parse(file, arm, code_ranges),
        _ => Ok(Vec::new()),
    }
}

fn parse<'data, Pe, R>(
    file: &PeFile<'data, Pe, R>,
    arm: bool,
    code_ranges: &[Range<u64>],
) -> Result<Vec<MetadataFunction>>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    let Some(export_table) = file.export_table().context("Read PE export table")? else {
        return Ok(Vec::new());
    };

    let name_pointers = export_table.name_pointers();
    ensure!(
        name_pointers.len() <= MAX_INVENTORY,
        "PE export name table exceeds the inventory limit"
    );
    let image_base = file.nt_headers().optional_header().image_base();
    let mut symbols = Vec::new();
    let mut name_bytes = 0_usize;

    for (name_pointer, address_index) in export_table.name_iter() {
        let address_rva = export_table
            .address_by_index(u32::from(address_index))
            .context("Read PE export address")?;
        if export_table.is_forward(address_rva) {
            continue;
        }

        let address = image_base
            .checked_add(u64::from(address_rva))
            .context("PE export address overflow")?;
        let address = normalize(address, arm);
        if !code_ranges.iter().any(|range| range.contains(&address)) {
            continue;
        }

        let name_bytes_value = export_table
            .name_from_pointer(name_pointer)
            .context("Read PE export name")?;
        let name = str::from_utf8(name_bytes_value).context("PE export name is not UTF-8")?;
        name_bytes = admit_name(name_bytes, name)?;

        symbols.push(MetadataFunction {
            address,
            name: Some(name.to_owned()),
        });
    }

    Ok(symbols)
}
