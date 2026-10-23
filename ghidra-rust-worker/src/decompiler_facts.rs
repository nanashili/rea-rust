//! Loader facts the decompiler needs to bound each function's flow.
//!
//! The engine follows fall-through after every call it cannot classify. A call
//! to an unnamed import stub such as `_Unwind_Resume` or `__stack_chk_fail`
//! therefore continues into unrelated code (exception landing pads, the next
//! function), producing very large, slow, and wrong pseudocode. Java Ghidra
//! avoids this by naming import thunks and marking non-returning functions.
//! This module supplies the same two facts to a decompiler Program: names for
//! Mach-O symbol stubs, and the non-returning property for known names.
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::OnceLock;

use anyhow::{Context, Result, ensure};
use ghidra_decompiler::address::Address;
use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::Program;
use object::Endian;
use object::read::macho::{LoadCommandVariant, MachHeader, MachOFile, Nlist, Segment};
use object::{BinaryFormat, Object, ObjectSection, SectionKind};

/// One Mach-O section header, reduced to the stub-binding fields.
struct StubSection {
    flags: u32,
    start: u64,
    size: u64,
    first: u32,
    stub_size: u32,
}

use crate::protocol::MAX_NAME_BYTES;

/// Upper bound on named stubs; each stub is one loader entry.
const MAX_STUBS: usize = crate::protocol::MAX_INVENTORY;

/// Names of functions that never return, compared after stripping leading
/// underscores (Ghidra's convention). Sources: Ghidra 12.1.4
/// `Ghidra/Features/Base/data/{MachO,Elf,PE}FunctionsThatDoNotReturn`, plus
/// the Itanium C++ ABI unwinder and rethrow entry points (`_Unwind_Resume`,
/// `__cxa_rethrow`), which that ABI defines as non-returning.
const MACHO_NO_RETURN: &[&str] = &[
    "exit", "cexit", "c_exit", "abort", "reboot", "longjmp", "siglongjmp", "panic",
    "stack_chk_fail", "objc_exception_throw", "cxa_throw", "yy_fatal_error",
    "Unwind_SjLj_Resume", "assert_rtn", "pthread_exit", "errx", "abort_message",
    "clang_call_terminate", "ZL11unreachablePKc", "ZN5swift10fatalErrorEjPKcz",
    "ZN5swift24swift_abortRetainUnownedEPKv", "ZN5swift25swift_abortRetainOverflowEv",
    "ZN5swift32swift_abortUnownedRetainOverflowEv",
    "ZN5swift24swift_dynamicCastFailureEPKNS_14TargetMetadataINS_9InProcessEEES4_PKc",
    "T0s18_fatalErrorMessages5NeverOs12StaticStringV_A2E4fileSu4lines6UInt32V5flagstFTf4nnddn_n",
    "T0s17_assertionFailures5NeverOs12StaticStringV_SSAE4fileSu4lines6UInt32V5flagstFTf4nxnnn_n",
    "T0s18_fatalErrorMessages5NeverOs12StaticStringV_A2E4fileSu4lines6UInt32V5flagstF",
    "T0s17_assertionFailures5NeverOs12StaticStringV_SSAE4fileSu4lines6UInt32V5flagstF",
    "T0s17_assertionFailures5NeverOs12StaticStringV_SSAE4fileSu4lines6UInt32V5flagstFTfq4nxnnn_n",
    "ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv",
    "ZNKSt3__121__basic_string_commonILb1EE20__throw_length_errorEv",
    "T0s9_abstracts5NeverOs12StaticStringV4file_Su4linetF",
    "ZN5swift24swift_dynamicCastFailureEPKvPKcS1_S3_S3_", "ZSt11__terminatePFvvE",
    "ZSt12__unexpectedPFvvE",
];
const ELF_NO_RETURN: &[&str] = &[
    "exit", "cexit", "c_exit", "abort", "reboot", "longjmp", "longjmp_chk", "siglongjmp",
    "panic", "stack_chk_fail", "cxa_throw", "cxa_bad_cast", "cxa_call_unexpected",
    "cxa_terminate", "assert_fail", "fortify_fail", "Unwind_Resume", "ZSt9terminatev",
    "ZN10__cxxabiv111__terminateEPFvvE", "quick_exit", "pthread_exit",
];
const PE_NO_RETURN: &[&str] = &[
    "abort", "CxxThrowException", "CxxThrowException@8", "CxxFrameHandler3",
    "crtExitProcess", "exit", "c_exit", "cexit", "ExitProcess", "ExitThread",
    "FreeLibraryAndExitThread", "ExRaiseAccessViolation", "ExRaiseDatatypeMisalignment",
    "ExRaiseStatus", "invalid_parameter_noinfo_noreturn", "invoke_watson", "KeBugCheck",
    "KeBugCheckEx", "longjmp", "quick_exit", "raise_securityfailure",
    "report_rangecheckfailure", "RpcRaiseException", "?terminate@@YAXXZ",
    "?_Xbad_alloc@std@@YAXXZ", "?_Xlength_error@std@@YAXPBD@Z",
    "?_Xout_of_range@std@@YAXPBD@Z", "?_Xbad_function_call@std@@YAXXZ",
];
/// Itanium C++ ABI non-returning entry points absent from Ghidra's Mach-O list.
const ITANIUM_NO_RETURN: &[&str] = &["Unwind_Resume", "cxa_rethrow"];

/// Call sites that fall directly into another function start before a callee
/// is treated as non-returning. Matches the default "Function Non-return
/// Threshold" of Ghidra's `FindNoReturnFunctionsAnalyzer`.
const NO_RETURN_EVIDENCE_THRESHOLD: usize = 3;

/// Longest x86 instruction; byte-aligned languages are searched up to this.
const MAX_BYTE_ALIGNED_INSTRUCTION: u64 = 15;

/// Facts computed once per admitted target image.
#[derive(Default)]
pub struct DecompilerFacts {
    /// `(stub address, imported symbol)` for every bound symbol stub.
    pub stubs: Vec<(u64, String)>,
    format: Option<BinaryFormat>,
    /// Executable section ranges, sorted by start. Instructions are decoded
    /// only inside them: decoding other bytes (for example header padding
    /// before the first function of `__text`) leaves the engine's decoder in
    /// a state that corrupts later decompiles of real code.
    code_ranges: Vec<Range<u64>>,
    /// Inventory entries discovered as non-returning from call-site evidence.
    /// Computed from the first Program with the session's frozen inventory;
    /// the pool owning these facts serves exactly one admitted target.
    discovered_no_return: OnceLock<Vec<u64>>,
}

impl DecompilerFacts {
    pub fn read(file: &object::File<'_>) -> Result<Self> {
        let stubs = match file {
            object::File::MachO32(file) => macho_stubs(file)?,
            object::File::MachO64(file) => macho_stubs(file)?,
            _ => Vec::new(),
        };
        let mut code_ranges: Vec<Range<u64>> = file
            .sections()
            .filter(|section| section.kind() == SectionKind::Text)
            .filter_map(|section| {
                let start = section.address();
                start.checked_add(section.size()).map(|end| start..end)
            })
            .filter(|range| !range.is_empty())
            .collect();
        code_ranges.sort_by_key(|range| range.start);
        Ok(Self {
            stubs,
            format: Some(file.format()),
            code_ranges,
            discovered_no_return: OnceLock::new(),
        })
    }

    /// Whether `[address, address + length)` lies inside one executable section.
    pub fn is_code(&self, address: u64, length: u64) -> bool {
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        let index = self.code_ranges.partition_point(|range| range.start <= address);
        index > 0 && self.code_ranges[index - 1].end >= end
    }

    fn no_return_names(&self) -> BTreeSet<&'static str> {
        let list: &[&[&str]] = match self.format {
            Some(BinaryFormat::MachO) => &[MACHO_NO_RETURN, ITANIUM_NO_RETURN],
            Some(BinaryFormat::Elf) => &[ELF_NO_RETURN, ITANIUM_NO_RETURN],
            Some(BinaryFormat::Pe) => &[PE_NO_RETURN],
            _ => &[],
        };
        list.iter().flat_map(|names| names.iter().copied()).collect()
    }

    /// Name stubs and mark non-returning functions in a decompiler Program.
    /// `starts` is the sorted frozen inventory. Returns the number of
    /// functions marked non-returning.
    pub fn apply(&self, program: &mut Program, starts: &[u64]) -> Result<usize> {
        for (address, name) in &self.stubs {
            program
                .set_function_name(*address, name)
                .map_err(|error| anyhow::anyhow!(error.explain().to_string()))
                .with_context(|| format!("Name the import stub at {address:#x}"))?;
        }
        let names = self.no_return_names();
        let mut entries = BTreeSet::new();
        for function in program
            .functions()
            .map_err(|error| anyhow::anyhow!(error.explain().to_string()))?
        {
            let raw = function.symbol.as_deref().unwrap_or(&function.name);
            if names.contains(raw.trim_start_matches('_'))
                || names.contains(function.name.trim_start_matches('_'))
            {
                entries.insert(function.address);
            }
        }
        let discovered = self
            .discovered_no_return
            .get_or_init(|| discover_no_return(program, starts, self));
        entries.extend(discovered.iter().copied());
        for entry in &entries {
            mark_no_return(program, *entry)?;
        }
        Ok(entries.len())
    }
}

/// Java Ghidra's "Non-Returning Functions - Discovered" evidence: a call
/// whose fall-through address is another function's entry cannot return
/// there, so its callee is a non-returning candidate. A callee with at least
/// [`NO_RETURN_EVIDENCE_THRESHOLD`] such call sites is non-returning.
///
/// Only the instruction ending exactly at each inventory entry is decoded.
/// Without this, flow after calls such as libc++'s local
/// `__throw_bad_variant_access` runs into the following functions and a
/// 100-byte function decompiles to hundreds of kilobytes.
fn discover_no_return(program: &mut Program, starts: &[u64], facts: &DecompilerFacts) -> Vec<u64> {
    let alignment = program
        .architecture()
        .translate
        .as_deref()
        .map_or(1, |translate| u64::try_from(translate.get_alignment().max(1)).unwrap_or(1));
    // Fixed-width languages place the preceding instruction exactly one unit
    // back; 2-byte-aligned languages (Thumb, MIPS16) also have 4-byte forms.
    let lengths: Vec<u64> = match alignment {
        1 => (1..=MAX_BYTE_ALIGNED_INSTRUCTION).collect(),
        2 => vec![2, 4],
        width => vec![width],
    };
    let mut votes: BTreeMap<u64, usize> = BTreeMap::new();
    for &start in starts {
        for &length in &lengths {
            let Some(site) = start.checked_sub(length) else {
                continue;
            };
            if !facts.is_code(site, length) {
                continue;
            }
            let Some(instruction) = program.pcode(site, 1).ok().and_then(|mut list| list.pop()) else {
                continue;
            };
            if instruction.length as u64 != length {
                continue;
            }
            for operation in &instruction.operations {
                if operation.opcode != OpCode::Call {
                    continue;
                }
                let Some(target) = operation.inputs.first() else {
                    continue;
                };
                if target.space != "const" && target.offset != start && starts.binary_search(&target.offset).is_ok() {
                    *votes.entry(target.offset).or_default() += 1;
                }
            }
        }
    }
    votes
        .into_iter()
        .filter_map(|(target, count)| (count >= NO_RETURN_EVIDENCE_THRESHOLD).then_some(target))
        .collect()
}

fn mark_no_return(program: &mut Program, entry: u64) -> Result<()> {
    let architecture = program.architecture();
    let space = architecture
        .manager
        .get_default_code_space()
        .context("Missing default code space")?;
    let address = Address::new(space, entry);
    let query = |program: &mut Program| -> Result<Option<_>> {
        let database = program
            .architecture()
            .symboltab
            .as_ref()
            .context("Missing decompiler symbol table")?;
        let scope = database
            .get_global_scope()
            .context("Missing decompiler global scope")?;
        Ok(database.scope_query_function(scope, &address))
    };
    let symbol = match query(program)? {
        Some(symbol) => symbol,
        None => {
            // An inventory entry without a loader symbol gets the same
            // default function the decompiler would create for it.
            program
                .set_function_name(entry, "")
                .map_err(|error| anyhow::anyhow!(error.explain().to_string()))
                .with_context(|| format!("Create the non-returning function at {entry:#x}"))?;
            query(program)?.context("A created function has no symbol")?
        }
    };
    program
        .architecture()
        .with_function(symbol, |function, _| {
            function.get_func_proto_mut().set_no_return(true);
            Ok(())
        })
        .map_err(|error| anyhow::anyhow!(error.explain().to_string()))
}

/// Mach-O `S_SYMBOL_STUBS` sections: stub `i` binds the symbol at indirect
/// symbol table index `reserved1 + i`, and each stub is `reserved2` bytes.
fn macho_stubs<'data, Mach: MachHeader>(file: &MachOFile<'data, Mach>) -> Result<Vec<(u64, String)>> {
    let endian = file.endian();
    let data = file.data();
    let mut indirect = None;
    let mut sections: Vec<StubSection> = Vec::new();
    let mut commands = file.macho_load_commands()?;
    while let Some(command) = commands.next()? {
        match command.variant()? {
            LoadCommandVariant::Dysymtab(dysymtab) => {
                ensure!(indirect.is_none(), "Duplicate Mach-O dynamic symbol table");
                let offset = dysymtab.indirectsymoff.get(endian) as usize;
                let count = dysymtab.nindirectsyms.get(endian) as usize;
                let end = count
                    .checked_mul(4)
                    .and_then(|bytes| bytes.checked_add(offset))
                    .context("Mach-O indirect symbol range overflow")?;
                indirect = Some(
                    data.get(offset..end)
                        .context("Invalid Mach-O indirect symbol range")?,
                );
            }
            LoadCommandVariant::Segment64(segment, section_data) => {
                for section in segment.sections(endian, section_data)? {
                    sections.push(StubSection {
                        flags: section.flags.get(endian),
                        start: section.addr.get(endian),
                        size: section.size.get(endian),
                        first: section.reserved1.get(endian),
                        stub_size: section.reserved2.get(endian),
                    });
                }
            }
            LoadCommandVariant::Segment32(segment, section_data) => {
                for section in segment.sections(endian, section_data)? {
                    sections.push(StubSection {
                        flags: section.flags.get(endian),
                        start: section.addr.get(endian).into(),
                        size: section.size.get(endian).into(),
                        first: section.reserved1.get(endian),
                        stub_size: section.reserved2.get(endian),
                    });
                }
            }
            _ => {}
        }
    }
    let Some(indirect) = indirect else {
        return Ok(Vec::new());
    };
    let symbols = file.macho_symbol_table();
    let strings = symbols.strings();
    let mut stubs = Vec::new();
    let mut seen = BTreeSet::new();
    for section in sections {
        {
            if section.flags & object::macho::SECTION_TYPE != object::macho::S_SYMBOL_STUBS {
                continue;
            }
            let stub_size = u64::from(section.stub_size);
            ensure!(stub_size > 0, "Mach-O symbol stubs have no entry size");
            let first = section.first as usize;
            let start = section.start;
            let size = section.size;
            for ordinal in 0..size / stub_size {
                let slot = first
                    .checked_add(ordinal as usize)
                    .context("Mach-O stub index overflow")?;
                let Some(entry) = indirect.get(slot * 4..slot * 4 + 4) else {
                    break;
                };
                let bytes = [entry[0], entry[1], entry[2], entry[3]];
                let index = if endian.is_big_endian() {
                    u32::from_be_bytes(bytes)
                } else {
                    u32::from_le_bytes(bytes)
                };
                if index & (object::macho::INDIRECT_SYMBOL_LOCAL | object::macho::INDIRECT_SYMBOL_ABS) != 0 {
                    continue;
                }
                let Ok(symbol) = symbols.symbol(object::SymbolIndex(index as usize)) else {
                    continue;
                };
                let Ok(name) = symbol.name(endian, strings) else {
                    continue;
                };
                let Ok(name) = std::str::from_utf8(name) else {
                    continue;
                };
                if name.is_empty() || name.len() > MAX_NAME_BYTES {
                    continue;
                }
                let address = start + ordinal * stub_size;
                if seen.insert(address) {
                    ensure!(stubs.len() < MAX_STUBS, "Mach-O stub inventory exceeds the limit");
                    stubs.push((address, name.to_owned()));
                }
            }
        }
    }
    Ok(stubs)
}
