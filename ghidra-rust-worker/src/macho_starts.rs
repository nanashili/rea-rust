use anyhow::{Context, Result, bail, ensure};
use object::read::macho::{MachHeader, MachOFile};
use object::{Object, ObjectSegment};

use crate::protocol::MAX_INVENTORY;

pub fn function_starts(file: &object::File<'_>) -> Result<Vec<u64>> {
    match file {
        object::File::MachO32(file) => parse(file),
        object::File::MachO64(file) => parse(file),
        _ => Ok(Vec::new()),
    }
}

fn parse<'data, Mach: MachHeader>(file: &MachOFile<'data, Mach>) -> Result<Vec<u64>> {
    let mut commands = file.macho_load_commands()?;
    let mut encoded = None;

    while let Some(command) = commands.next()? {
        if command.cmd() != object::macho::LC_FUNCTION_STARTS {
            continue;
        }

        ensure!(
            encoded.is_none(),
            "Duplicate Mach-O function-start commands"
        );
        let data = command.data::<object::macho::LinkeditDataCommand<Mach::Endian>>()?;
        let start = data.dataoff.get(file.endian()) as usize;
        let size = data.datasize.get(file.endian()) as usize;
        let end = start
            .checked_add(size)
            .context("Mach-O function-start range overflow")?;
        encoded = Some(
            file.data()
                .get(start..end)
                .context("Invalid Mach-O function-start range")?,
        );
    }

    let Some(encoded) = encoded.filter(|bytes| !bytes.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut base = None;
    for segment in file.segments() {
        if segment.name()? == Some("__TEXT") {
            ensure!(base.is_none(), "Ambiguous Mach-O __TEXT base");
            base = Some(segment.address());
        }
    }

    decode(encoded, base.context("Missing Mach-O __TEXT base")?)
}

fn decode(mut bytes: &[u8], mut current: u64) -> Result<Vec<u64>> {
    let mut addresses = Vec::new();
    while !bytes.is_empty() {
        let delta = read_uleb128(&mut bytes)?;
        if delta == 0 {
            ensure!(
                bytes.iter().all(|byte| *byte == 0),
                "Trailing Mach-O function-start data"
            );
            return Ok(addresses);
        }

        ensure!(
            addresses.len() < MAX_INVENTORY,
            "Function-start inventory exceeds the limit"
        );
        current = current
            .checked_add(delta)
            .context("Mach-O function-start address overflow")?;
        addresses.push(current);
    }

    bail!("Unterminated Mach-O function-start metadata")
}

fn read_uleb128(bytes: &mut &[u8]) -> Result<u64> {
    let mut value = 0_u64;
    for shift in (0..=63).step_by(7) {
        let (&byte, remaining) = bytes
            .split_first()
            .context("Truncated ULEB128 address delta")?;
        *bytes = remaining;
        let payload = u64::from(byte & 0x7f);
        ensure!(
            payload <= u64::MAX >> shift,
            "ULEB128 address delta overflow"
        );
        value |= payload << shift;

        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }

    bail!("ULEB128 address delta is too long")
}
