use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use ghidra_decompiler::program::{Program, SymbolLoading};
use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
use object::{Architecture, BinaryFormat, Object, ObjectSection, SectionKind};

use crate::encoding::encoded_size;
use crate::macho_starts;
use crate::protocol::{MAX_BATCH_BYTES, MAX_NAME_BYTES, Segment, address};

pub struct TargetImage {
    pub bytes: Vec<u8>,
    pub sections: Vec<Segment>,
    pub metadata_functions: Vec<u64>,
    pub go_build_id_markers: Vec<u64>,
    /// Executable section ranges that admit inventory entries.
    pub code_ranges: Vec<Range<u64>>,
    pub arm: bool,
}

#[derive(Debug)]
pub(crate) struct SelectedImage {
    pub bytes: Vec<u8>,
    pub file_offset: u64,
    pub architecture: Architecture,
}

impl TargetImage {
    pub fn read(path: &Path, expected_sha256: &str) -> Result<Self> {
        let selected = read_selected_image(path, expected_sha256)?;
        let bytes = selected.bytes;
        let file = object::File::parse(bytes.as_slice())
            .context("Expected a supported ELF, PE, or Mach-O image")?;
        ensure!(
            file.architecture() == selected.architecture,
            "Selected Mach-O slice architecture does not match its payload"
        );
        ensure!(
            matches!(
                file.format(),
                BinaryFormat::Elf | BinaryFormat::Pe | BinaryFormat::MachO
            ),
            "Unsupported object format"
        );
        ensure!(
            matches!(
                file.architecture(),
                Architecture::I386
                    | Architecture::X86_64
                    | Architecture::Arm
                    | Architecture::Aarch64
            ),
            "Unsupported instruction architecture"
        );

        let (sections, code_ranges) = read_sections(&file)?;
        let arm = file.architecture() == Architecture::Arm;
        let go_build_id_markers = go_build_id_markers(&file);
        let mut metadata_functions = macho_starts::function_starts(&file)?;
        if file.entry() != 0 {
            metadata_functions.push(file.entry());
        }
        let address_mask = if arm { !1 } else { !0 };
        metadata_functions.retain(|value| {
            code_ranges
                .iter()
                .any(|range| range.contains(&(*value & address_mask)))
                && !go_build_id_markers.contains(&(*value & address_mask))
        });

        Ok(Self {
            bytes,
            sections,
            metadata_functions,
            go_build_id_markers,
            code_ranges,
            arm,
        })
    }
}

fn go_build_id_markers(file: &object::File<'_>) -> Vec<u64> {
    if file.format() != BinaryFormat::MachO {
        return Vec::new();
    }
    file.sections()
        .filter_map(|section| {
            (section.name().ok() == Some("__text")
                && section
                    .data()
                    .ok()
                    .and_then(|data| data.get(..16))
                    .is_some_and(|prefix| prefix == b"\xff Go build ID: \""))
            .then_some(section.address())
        })
        .collect()
}

/// Verify the caller's digest against the complete artifact, then select one
/// architecture from a universal Mach-O before handing bytes to `object` and
/// the decompiler. The selected slice is a view of the authenticated file;
/// no executable is launched and the original path and digest remain the
/// worker's identity.
pub(crate) fn read_selected_image(path: &Path, expected_sha256: &str) -> Result<SelectedImage> {
    let bytes = crate::target_file::read(path, expected_sha256)?;
    select_universal_slice(bytes)
}

fn select_universal_slice(bytes: Vec<u8>) -> Result<SelectedImage> {
    let kind = object::FileKind::parse(bytes.as_slice()).ok();
    match kind {
        Some(object::FileKind::MachOFat32) => {
            let fat = MachOFatFile32::parse(bytes.as_slice())
                .context("Parse the universal Mach-O architecture table")?;
            select_fat_arches(&bytes, fat.arches(), 8 + fat.arches().len() * 20)
        }
        Some(object::FileKind::MachOFat64) => {
            let fat = MachOFatFile64::parse(bytes.as_slice())
                .context("Parse the universal Mach-O architecture table")?;
            select_fat_arches(&bytes, fat.arches(), 8 + fat.arches().len() * 32)
        }
        _ => {
            let architecture = object::File::parse(bytes.as_slice())?.architecture();
            Ok(SelectedImage {
                bytes,
                file_offset: 0,
                architecture,
            })
        }
    }
}

fn select_fat_arches<Fat>(bytes: &[u8], arches: &[Fat], table_end: usize) -> Result<SelectedImage>
where
    Fat: FatArch,
{
    let mut ranges = Vec::with_capacity(arches.len());
    let mut candidates = Vec::new();

    for arch in arches {
        let (offset, size) = arch.file_range();
        validate_fat_range(bytes.len(), offset, size, arch.align())?;
        let end = offset + size;
        ensure!(
            offset >= table_end as u64,
            "Universal Mach-O slice overlaps the architecture table"
        );
        ensure!(
            ranges
                .iter()
                .all(|(range_start, range_end)| *range_end <= offset || *range_start >= end),
            "Universal Mach-O slices overlap"
        );
        ranges.push((offset, end));

        let architecture = arch.architecture();
        if !supported_architecture(architecture) {
            continue;
        }
        let payload = arch.data(bytes).context("Read universal Mach-O slice")?;
        let file =
            object::File::parse(payload).context("Parse the selected universal Mach-O slice")?;
        ensure!(
            file.format() == BinaryFormat::MachO && file.architecture() == architecture,
            "Universal Mach-O slice CPU does not match its payload"
        );
        candidates.push((architecture, offset, payload));
    }

    let host = host_architecture();
    let (architecture, offset, payload) = candidates
        .iter()
        .find(|(architecture, _, _)| *architecture == host)
        .or_else(|| candidates.first())
        .context("Universal Mach-O has no supported valid slice")?;
    Ok(SelectedImage {
        bytes: payload.to_vec(),
        file_offset: *offset,
        architecture: *architecture,
    })
}

fn validate_fat_range(file_length: usize, offset: u64, size: u64, align: u32) -> Result<()> {
    ensure!(size > 0, "Universal Mach-O slice is empty");
    ensure!(align < 63, "Universal Mach-O slice alignment is invalid");
    let alignment = 1_u64 << align;
    ensure!(
        offset % alignment == 0,
        "Universal Mach-O slice is misaligned"
    );
    let end = offset
        .checked_add(size)
        .context("Universal Mach-O slice range overflows")?;
    ensure!(
        end <= file_length as u64,
        "Universal Mach-O slice extends beyond the artifact"
    );
    Ok(())
}

fn supported_architecture(architecture: Architecture) -> bool {
    matches!(
        architecture,
        Architecture::I386 | Architecture::X86_64 | Architecture::Arm | Architecture::Aarch64
    )
}

fn host_architecture() -> Architecture {
    match std::env::consts::ARCH {
        "aarch64" => Architecture::Aarch64,
        "x86_64" => Architecture::X86_64,
        "arm" => Architecture::Arm,
        "x86" => Architecture::I386,
        _ => Architecture::Unknown,
    }
}

pub fn load_program(path: &Path, bytes: Vec<u8>) -> Result<Program> {
    let mut program =
        Program::from_image_with(&path.to_string_lossy(), bytes, None, SymbolLoading::Loader)
            .context("Initialize the Rust Ghidra loader")?;
    program.architecture().max_instructions = 65_536;
    program.architecture().flowoptions |= ghidra_decompiler::flow::ERROR_TOOMANYINSTRUCTIONS;
    Ok(program)
}

fn read_sections(file: &object::File<'_>) -> Result<(Vec<Segment>, Vec<Range<u64>>)> {
    let mut sections = Vec::new();
    let mut code_ranges = Vec::new();
    let mut encoded_bytes = 0;
    for section in file.sections() {
        ensure!(
            sections.len() < 4096,
            "Section list exceeds the protocol limit"
        );
        let name = section.name().context("Section name is not UTF-8")?;
        ensure!(
            name.len() <= MAX_NAME_BYTES,
            "Section name exceeds the protocol limit"
        );
        let end = section
            .address()
            .checked_add(section.size())
            .context("Section address overflow")?;
        let executable = section.kind() == SectionKind::Text;
        if executable {
            code_ranges.push(section.address()..end);
        }
        let segment = Segment {
            name: name.to_owned(),
            address: address(section.address()),
            end: address(end),
            executable,
        };
        encoded_bytes += encoded_size(&segment)?;
        ensure!(
            encoded_bytes <= MAX_BATCH_BYTES,
            "Section metadata exceeds the output budget"
        );
        sections.push(segment);
    }
    Ok((sections, code_ranges))
}

#[cfg(test)]
mod tests {
    use super::select_universal_slice;

    fn thin_arm64_image() -> Vec<u8> {
        let mut image = Vec::from([0xcf, 0xfa, 0xed, 0xfe]);
        image.extend_from_slice(&0x0100_000c_u32.to_le_bytes());
        image.extend_from_slice(&0_u32.to_le_bytes());
        image.extend_from_slice(&2_u32.to_le_bytes());
        image.extend_from_slice(&1_u32.to_le_bytes());
        image.extend_from_slice(&72_u32.to_le_bytes());
        image.extend_from_slice(&0_u32.to_le_bytes());
        image.extend_from_slice(&0_u32.to_le_bytes());
        image.extend_from_slice(&[0x19, 0, 0, 0]);
        image.extend_from_slice(&72_u32.to_le_bytes());
        image.extend_from_slice(&[0; 16]);
        image.extend_from_slice(&0_u64.to_le_bytes());
        image.extend_from_slice(&4_u64.to_le_bytes());
        image.extend_from_slice(&0_u64.to_le_bytes());
        image.extend_from_slice(&4_u64.to_le_bytes());
        image.extend_from_slice(&7_u32.to_le_bytes());
        image.extend_from_slice(&5_u32.to_le_bytes());
        image.extend_from_slice(&0_u32.to_le_bytes());
        image.extend_from_slice(&0_u32.to_le_bytes());
        image
    }

    #[test]
    fn selects_a_valid_fat32_slice_and_preserves_file_offset() {
        let thin = thin_arm64_image();
        let offset = 0x4000_usize;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xcafebabe_u32.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&0x0100_000c_u32.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&(offset as u32).to_be_bytes());
        bytes.extend_from_slice(&(thin.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&14_u32.to_be_bytes());
        bytes.resize(offset, 0);
        bytes.resize(offset + thin.len(), 0);
        bytes[offset..].copy_from_slice(&thin);

        let selected = select_universal_slice(bytes).expect("valid universal image");
        assert_eq!(selected.file_offset, offset as u64);
        assert_eq!(selected.bytes, thin);
    }

    #[test]
    fn rejects_a_universal_slice_with_invalid_bounds() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xcafebabe_u32.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&0x0100_000c_u32.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&0x4000_u32.to_be_bytes());
        bytes.extend_from_slice(&4_u32.to_be_bytes());
        bytes.extend_from_slice(&14_u32.to_be_bytes());

        let error = select_universal_slice(bytes).expect_err("unsupported CPU must fail");
        assert!(error.to_string().contains("extends beyond"));
    }

    #[test]
    fn selects_a_valid_fat64_slice_from_a_thin_macho_fixture() {
        let thin = thin_arm64_image();
        let offset = 0x4000_usize;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xcafebabf_u32.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&0x0100_000c_u32.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&(offset as u64).to_be_bytes());
        bytes.extend_from_slice(&(thin.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&14_u32.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.resize(offset, 0);
        bytes.resize(offset + thin.len(), 0);
        bytes[offset..].copy_from_slice(&thin);

        let selected = select_universal_slice(bytes).expect("valid universal image");
        assert_eq!(selected.file_offset, offset as u64);
        assert_eq!(selected.bytes, thin);
    }

    #[test]
    fn accepts_descending_non_overlapping_fat_entries() {
        let thin = thin_arm64_image();
        let high = 0x8000_usize;
        let low = 0x4000_usize;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xcafebabe_u32.to_be_bytes());
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        for offset in [high, low] {
            bytes.extend_from_slice(&0x0100_000c_u32.to_be_bytes());
            bytes.extend_from_slice(&0_u32.to_be_bytes());
            bytes.extend_from_slice(&(offset as u32).to_be_bytes());
            bytes.extend_from_slice(&(thin.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&14_u32.to_be_bytes());
        }
        bytes.resize(high + thin.len(), 0);
        bytes[high..high + thin.len()].copy_from_slice(&thin);
        bytes[low..low + thin.len()].copy_from_slice(&thin);

        let selected = select_universal_slice(bytes).expect("descending entries are valid");
        assert_eq!(selected.bytes, thin);
    }

    #[test]
    fn rejects_overlapping_fat_entries_before_parsing_payloads() {
        let thin = thin_arm64_image();
        let offset = 0x4000_usize;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xcafebabe_u32.to_be_bytes());
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        for _ in 0..2 {
            bytes.extend_from_slice(&0x0100_000c_u32.to_be_bytes());
            bytes.extend_from_slice(&0_u32.to_be_bytes());
            bytes.extend_from_slice(&(offset as u32).to_be_bytes());
            bytes.extend_from_slice(&(thin.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&14_u32.to_be_bytes());
        }
        bytes.resize(offset + thin.len(), 0);
        bytes[offset..].copy_from_slice(&thin);

        let error = select_universal_slice(bytes).expect_err("overlap must fail");
        assert!(error.to_string().contains("slices overlap"));
    }
}
