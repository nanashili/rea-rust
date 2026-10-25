use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use ghidra_decompiler::program::{Program, SymbolLoading};
use object::{Architecture, BinaryFormat, Object, ObjectSection, SectionKind};

use crate::encoding::encoded_size;
use crate::inventory::{MetadataFunction, normalize};
use crate::protocol::{MAX_BATCH_BYTES, MAX_INVENTORY, MAX_NAME_BYTES, Segment, address};
use crate::{macho_starts, pe_exports};

pub struct TargetImage {
    pub bytes: Vec<u8>,
    pub sections: Vec<Segment>,
    pub metadata_functions: Vec<MetadataFunction>,
    /// Executable section ranges that admit inventory entries.
    pub code_ranges: Vec<Range<u64>>,
    pub arm: bool,
}

impl TargetImage {
    pub fn read(path: &Path, expected_sha256: &str) -> Result<Self> {
        let bytes = crate::target_file::read(path, expected_sha256)?;
        let file = object::File::parse(bytes.as_slice()).context(
            "Expected a supported thin ELF, PE, or Mach-O image; universal images are rejected",
        )?;
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
        let metadata_functions = read_function_metadata(&file, arm, &code_ranges)?;

        Ok(Self {
            bytes,
            sections,
            metadata_functions,
            code_ranges,
            arm,
        })
    }
}

fn read_function_metadata(
    file: &object::File<'_>,
    arm: bool,
    code_ranges: &[Range<u64>],
) -> Result<Vec<MetadataFunction>> {
    let mut addresses = macho_starts::function_starts(file)?;
    if file.entry() != 0 {
        addresses.push(file.entry());
    }
    addresses.retain(|value| {
        code_ranges
            .iter()
            .any(|range| range.contains(&normalize(*value, arm)))
    });

    let mut functions = pe_exports::function_symbols(file, arm, code_ranges)?;
    ensure!(
        functions.len() + addresses.len() <= MAX_INVENTORY,
        "Function metadata exceeds the inventory limit"
    );
    functions.extend(addresses.into_iter().map(|address| MetadataFunction {
        address,
        name: None,
    }));
    Ok(functions)
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
