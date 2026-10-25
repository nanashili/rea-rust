//! Strings, derived references, instruction listings and byte reads for the
//! admitted target.
pub(crate) mod byte_search;
pub(crate) mod image;
pub(crate) mod instruction;
pub(crate) mod references;

use std::collections::BTreeSet;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, ensure};
use ghidra_decompiler::opcodes::OpCode;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::decompiler_facts::DecompilerFacts;
use crate::protocol::{address, parse_address};
use crate::session::Session;
use crate::target::load_program;
use crate::transport::Progress;
use ghidra_decompiler::program::Program;
use image::ImageString;
use references::{Kind, Mapped, Reference};

/// Strings per `strings` page.
pub(crate) const MAX_STRING_PAGE: usize = 1024;
/// References per `references_to` / `references_from` page.
pub(crate) const MAX_REFERENCE_PAGE: usize = 4096;
/// Instructions per `instructions` page.
pub(crate) const MAX_INSTRUCTION_PAGE: usize = 4096;

fn merge_ranges(mut ranges: Vec<Range<u64>>) -> Vec<Range<u64>> {
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    merged
}

const MAX_FUNCTION_BODY_INSTRUCTIONS: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BranchTarget {
    Direct(u64),
    Internal,
    Computed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BodyInstruction {
    length: u64,
    has_return: bool,
    unconditional: Option<BranchTarget>,
    conditional: Option<BranchTarget>,
    ambiguous_control: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyDecodeError {
    Decode,
    Pcode,
}

#[derive(Debug, PartialEq, Eq)]
struct FunctionBodyResult {
    complete: bool,
    reason: &'static str,
    block_starts: BTreeSet<u64>,
    ranges: Vec<Range<u64>>,
}

fn mark_incomplete(result: &mut FunctionBodyResult, reason: &'static str) {
    if result.complete {
        result.complete = false;
        result.reason = reason;
    }
}

fn crosses_inventory_boundary(function_starts: &[u64], start: u64, end: u64) -> bool {
    let first = function_starts.partition_point(|candidate| *candidate <= start);
    function_starts[first..]
        .iter()
        .any(|candidate| *candidate < end)
}

fn queue_branch_target(
    result: &mut FunctionBodyResult,
    pending: &mut Vec<u64>,
    branch_targets: &mut BTreeSet<u64>,
    entry: u64,
    function_starts: &[u64],
    target: BranchTarget,
) {
    match target {
        BranchTarget::Internal => mark_incomplete(result, "internal-branch"),
        BranchTarget::Computed => mark_incomplete(result, "computed-branch"),
        BranchTarget::Direct(target) => {
            if target != entry && function_starts.binary_search(&target).is_ok() {
                mark_incomplete(result, "inventory-boundary");
            } else if result
                .ranges
                .iter()
                .any(|range| range.start < target && target < range.end)
            {
                mark_incomplete(result, "misaligned-target");
            } else if result.ranges.iter().any(|range| range.start == target) {
                result.block_starts.insert(target);
            } else {
                branch_targets.insert(target);
                pending.push(target);
            }
        }
    }
}

fn walk_function_body(
    entry: u64,
    function_starts: &[u64],
    mut decode: impl FnMut(u64) -> std::result::Result<Option<BodyInstruction>, BodyDecodeError>,
) -> FunctionBodyResult {
    let mut result = FunctionBodyResult {
        complete: true,
        reason: "reachable-control-flow-covered",
        block_starts: BTreeSet::new(),
        ranges: Vec::new(),
    };
    let mut pending = vec![entry];
    let mut scheduled = BTreeSet::new();
    let mut branch_targets = BTreeSet::new();
    let mut visited = std::collections::BTreeSet::new();
    let mut instruction_count = 0_usize;

    while let Some(block_start) = pending.pop() {
        if result
            .ranges
            .iter()
            .any(|range| range.start < block_start && block_start < range.end)
        {
            mark_incomplete(&mut result, "misaligned-target");
            continue;
        }
        if !scheduled.insert(block_start) {
            continue;
        }

        let mut current = block_start;
        loop {
            if instruction_count >= MAX_FUNCTION_BODY_INSTRUCTIONS {
                mark_incomplete(&mut result, "instruction-limit");
                break;
            }
            if current != block_start && branch_targets.contains(&current) {
                pending.push(current);
                break;
            }
            if !visited.insert(current) {
                break;
            }

            let decoded = match decode(current) {
                Ok(instruction) => instruction,
                Err(BodyDecodeError::Decode) => {
                    mark_incomplete(&mut result, "decode-failure");
                    None
                }
                Err(BodyDecodeError::Pcode) => {
                    mark_incomplete(&mut result, "pcode-failure");
                    None
                }
            };
            let Some(instruction) = decoded else {
                if !result.complete {
                    break;
                }
                mark_incomplete(&mut result, "non-code-boundary");
                break;
            };
            if instruction.length == 0 {
                mark_incomplete(&mut result, "decode-failure");
                break;
            }
            let Some(end) = current.checked_add(instruction.length) else {
                mark_incomplete(&mut result, "address-overflow");
                break;
            };
            if crosses_inventory_boundary(function_starts, current, end) {
                mark_incomplete(&mut result, "inventory-boundary");
                break;
            }
            result.ranges.push(current..end);
            if current == block_start {
                result.block_starts.insert(block_start);
            }
            instruction_count += 1;

            if instruction.ambiguous_control {
                mark_incomplete(&mut result, "ambiguous-control");
                break;
            }

            if instruction.has_return {
                break;
            }

            if let Some(target) = instruction.unconditional {
                queue_branch_target(
                    &mut result,
                    &mut pending,
                    &mut branch_targets,
                    entry,
                    function_starts,
                    target,
                );
                break;
            }

            if let Some(target) = instruction.conditional {
                queue_branch_target(
                    &mut result,
                    &mut pending,
                    &mut branch_targets,
                    entry,
                    function_starts,
                    target,
                );
                if function_starts.binary_search(&end).is_ok() {
                    mark_incomplete(&mut result, "inventory-boundary");
                } else {
                    pending.push(end);
                }
                break;
            }

            if function_starts.binary_search(&end).is_ok() {
                mark_incomplete(&mut result, "inventory-boundary");
                break;
            }
            current = end;
        }
    }

    result
}

fn direct_branch_target(operation: &ghidra_decompiler::program::PcodeOperation) -> Option<u64> {
    if !matches!(operation.opcode, OpCode::Branch | OpCode::Cbranch) {
        return None;
    }
    operation
        .inputs
        .first()
        .filter(|input| input.space == "ram" || input.space == "default")
        .map(|input| input.offset)
}

fn branch_target(operation: &ghidra_decompiler::program::PcodeOperation) -> BranchTarget {
    if let Some(target) = direct_branch_target(operation) {
        return BranchTarget::Direct(target);
    }

    if operation
        .inputs
        .first()
        .is_some_and(|input| input.space == "const")
    {
        return BranchTarget::Internal;
    }

    BranchTarget::Computed
}

fn decode_body_instruction(
    program: &Program,
    facts: &DecompilerFacts,
    current: u64,
) -> std::result::Result<Option<BodyInstruction>, BodyDecodeError> {
    if !facts.is_code(current, 1) {
        return Ok(None);
    }

    let instruction = program
        .disassemble(current, 1)
        .map_err(|_| BodyDecodeError::Decode)?
        .pop()
        .ok_or(BodyDecodeError::Decode)?;
    if instruction.length == 0 {
        return Err(BodyDecodeError::Decode);
    }

    let pcode = program
        .pcode(current, 1)
        .map_err(|_| BodyDecodeError::Pcode)?
        .pop()
        .ok_or(BodyDecodeError::Pcode)?;
    if pcode.length != instruction.length {
        return Err(BodyDecodeError::Pcode);
    }

    let mut decoded = BodyInstruction {
        length: instruction.length as u64,
        has_return: false,
        unconditional: None,
        conditional: None,
        ambiguous_control: false,
    };
    let mut control_operation_seen = false;

    for operation in pcode.operations {
        let control = match operation.opcode {
            OpCode::Return => Some((None, None, true)),
            OpCode::Branch => Some((Some(branch_target(&operation)), None, false)),
            OpCode::Cbranch => Some((None, Some(branch_target(&operation)), false)),
            OpCode::Branchind => Some((Some(BranchTarget::Computed), None, false)),
            _ => None,
        };
        let Some((unconditional, conditional, has_return)) = control else {
            continue;
        };

        if control_operation_seen {
            decoded.ambiguous_control = true;
        }
        control_operation_seen = true;
        decoded.has_return = has_return;
        decoded.unconditional = unconditional;
        decoded.conditional = conditional;
    }

    Ok(Some(decoded))
}

/// Lazily derived per-session facts. References are saved in the cache;
/// strings and file ranges are recomputed from the verified image.
#[derive(Default)]
pub(crate) struct AnalysisState {
    strings: Option<Arc<Vec<ImageString>>>,
    strings_sha256: Option<String>,
    file_ranges: Option<Arc<Vec<(Range<u64>, usize)>>>,
    references: Option<crate::cache::ReferenceManifest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddressPage {
    pub address: String,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ByteRead {
    pub address: String,
    pub length: usize,
}

pub(crate) const MAX_SEARCH_RESULTS: usize = 1000;
pub(crate) const MAX_SEARCH_PATTERN: usize = 4096;

pub(crate) fn numeric(text: &str) -> Result<u64> {
    let value = parse_address(text).context("Expected a canonical address")?;
    ensure!(address(value) == text, "Expected a canonical address");
    Ok(value)
}

fn reference_json(reference: &Reference) -> Value {
    json!({
        "function": address(reference.function),
        "source": address(reference.source),
        "target": (reference.kind != Kind::IndirectCall).then(|| address(reference.target)),
        "kind": reference.kind.name(),
    })
}

fn strings_digest(strings: &[ImageString]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"rea-rust-ghidra-strings-v1\0");
    for string in strings {
        hash.update(string.address.to_be_bytes());
        hash.update((string.value.len() as u64).to_be_bytes());
        hash.update(string.value.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

impl Session {
    pub fn search_bytes(&mut self, input: Value) -> Result<Value> {
        byte_search::search(self, input)
    }

    pub fn image_map(&mut self) -> Result<Value> {
        let (bytes, _, file_offset) = self.decompiler.verified_image()?;
        let ranges = image::coverage_ranges(&bytes, file_offset)?;
        let items = ranges
            .iter()
            .map(|range| {
                json!({
                    "start": address(range.address.start),
                    "end": address(range.address.end.saturating_sub(1)),
                    "file_offset": range.file_offset,
                    "length": range.address.end.saturating_sub(range.address.start),
                    "section": range.name,
                    "initialized": range.initialized,
                    "loaded": range.loaded,
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({"items": items, "coverage": "file-backed object sections"}))
    }

    fn image_strings(&mut self) -> Result<Arc<Vec<ImageString>>> {
        if self.analysis.strings.is_none() {
            let (bytes, _, _) = self.decompiler.verified_image()?;
            let strings = image::strings(&bytes)?;
            self.analysis.strings_sha256 = Some(strings_digest(&strings));
            self.analysis.strings = Some(Arc::new(strings));
        }
        Ok(Arc::clone(
            self.analysis
                .strings
                .as_ref()
                .expect("strings were just read"),
        ))
    }

    /// One page of the string inventory.
    pub fn strings(&mut self, page: crate::protocol::PageParams) -> Result<Value> {
        ensure!(
            (1..=MAX_STRING_PAGE).contains(&page.limit),
            "Invalid string page size"
        );
        let strings = self.image_strings()?;
        ensure!(
            page.offset <= strings.len(),
            "Offset exceeds the string inventory"
        );
        let items: Vec<Value> = strings[page.offset..]
            .iter()
            .take(page.limit)
            .map(|string| {
                json!({
                    "address": address(string.address),
                    "value": string.value,
                    "byte_length": string.byte_length,
                })
            })
            .collect();
        let next = page.offset + items.len();
        Ok(json!({
            "items": items,
            "offset": page.offset,
            "next_offset": (next < strings.len()).then_some(next),
            "total": strings.len(),
            "strings_sha256": self.analysis.strings_sha256,
        }))
    }

    /// Derive and save references for the whole inventory once.
    fn ensure_references(&mut self, progress: &mut impl Progress) -> Result<()> {
        if self.analysis.references.is_some() {
            return Ok(());
        }
        if let Some(manifest) = self.cache.reference_manifest(&self.snapshot)? {
            self.analysis.references = Some(manifest);
            return Ok(());
        }
        let starts = self.entry_addresses()?;
        let (bytes, facts, _) = self.decompiler.verified_image()?;
        let mapped = Arc::new(Mapped::new(
            self.snapshot
                .segments
                .iter()
                .filter_map(|segment| {
                    Some(parse_address(&segment.address)?..parse_address(&segment.end)?)
                })
                .collect(),
        ));
        let threads = self.decompiler.threads().min(starts.len().max(1));
        let path = self.decompiler.path().to_path_buf();
        let cursor = AtomicUsize::new(0);
        let completed = AtomicUsize::new(0);
        let total = starts.len();
        progress.report("Deriving references", 0, Some(total))?;
        let mut collected: Vec<Reference> = Vec::new();
        std::thread::scope(|scope| -> Result<()> {
            let handles = (0..threads)
                .map(|_| {
                    let (bytes, facts, mapped, starts, path) = (
                        Arc::clone(&bytes),
                        Arc::clone(&facts),
                        Arc::clone(&mapped),
                        Arc::clone(&starts),
                        &path,
                    );
                    let (cursor, completed) = (&cursor, &completed);
                    std::thread::Builder::new()
                        .name("rea-ghidra-references".to_owned())
                        .spawn_scoped(scope, move || -> Result<Vec<Reference>> {
                            let program = load_program(path, bytes.as_ref().clone())?;
                            let mut found = Vec::new();
                            loop {
                                let index = cursor.fetch_add(1, Ordering::AcqRel);
                                let Some(&entry) = starts.get(index) else {
                                    break;
                                };
                                found.extend(references::sweep(
                                    &program, &facts, &mapped, &starts, entry,
                                ));
                                completed.fetch_add(1, Ordering::AcqRel);
                            }
                            Ok(found)
                        })
                })
                .collect::<std::io::Result<Vec<_>>>()?;
            let mut last = 0;
            while handles.iter().any(|handle| !handle.is_finished()) {
                std::thread::sleep(std::time::Duration::from_millis(250));
                let done = completed.load(Ordering::Acquire);
                if done >= last + 4096 {
                    last = done;
                    // A failed progress delivery must not abandon the threads.
                    let _ = progress.report("Deriving references", done, Some(total));
                }
            }
            for handle in handles {
                let found = handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("A reference thread stopped unexpectedly"))??;
                collected.extend(found);
            }
            Ok(())
        })?;
        collected.sort();
        collected.dedup();
        progress.report("Saving references", total, Some(total))?;
        let manifest = self.cache.save_references(&self.snapshot, &collected)?;
        self.analysis.references = Some(manifest);
        Ok(())
    }

    /// References to `address` (code and data).
    pub fn references_to(
        &mut self,
        input: AddressPage,
        progress: &mut impl Progress,
    ) -> Result<Value> {
        ensure!(
            (1..=MAX_REFERENCE_PAGE).contains(&input.limit),
            "Invalid reference page size"
        );
        let target = numeric(&input.address)?;
        self.ensure_references(progress)?;
        let (items, total) = self
            .cache
            .references_to(target, input.offset, input.limit)?;
        Ok(self.reference_page(&input, &items, total))
    }

    /// References from instructions of the inventory function at `address`.
    pub fn references_from(
        &mut self,
        input: AddressPage,
        progress: &mut impl Progress,
    ) -> Result<Value> {
        ensure!(
            (1..=MAX_REFERENCE_PAGE).contains(&input.limit),
            "Invalid reference page size"
        );
        let function = numeric(&input.address)?;
        let starts = self.entry_addresses()?;
        ensure!(
            starts.binary_search(&function).is_ok(),
            "Address is absent from the saved inventory"
        );
        self.ensure_references(progress)?;
        let (items, total) = self
            .cache
            .references_from(function, input.offset, input.limit)?;
        Ok(self.reference_page(&input, &items, total))
    }

    fn reference_page(&self, input: &AddressPage, items: &[Reference], total: usize) -> Value {
        let next = input.offset + items.len();
        let manifest = self.analysis.references.as_ref();
        json!({
            "items": items.iter().map(reference_json).collect::<Vec<_>>(),
            "offset": input.offset,
            "next_offset": (next < total).then_some(next),
            "total": total,
            "references_sha256": manifest.map(|manifest| manifest.sha256.clone()),
            "indexed_references": manifest.map(|manifest| manifest.references),
            "inventory_sha256": self.snapshot.inventory_sha256,
        })
    }

    /// Linear disassembly of the inventory function at `address`, from its
    /// entry to the next inventory entry inside executable sections.
    pub fn instructions(&mut self, input: AddressPage) -> Result<Value> {
        ensure!(
            (1..=MAX_INSTRUCTION_PAGE).contains(&input.limit),
            "Invalid instruction page size"
        );
        let entry = numeric(&input.address)?;
        let starts = self.entry_addresses()?;
        ensure!(
            starts.binary_search(&entry).is_ok(),
            "Address is absent from the saved inventory"
        );
        let next = starts.partition_point(|start| *start <= entry);
        let end = starts.get(next).copied().unwrap_or(u64::MAX);
        let (items, exhausted, stop) =
            self.decompiler.with_program(&starts, |program, facts| {
                let mut items = Vec::new();
                let mut current = entry;
                let mut index = 0_usize;
                let mut stop = "next_entry";
                loop {
                    if current >= end {
                        break;
                    }
                    if !facts.is_code(current, 1) {
                        stop = "end_of_code";
                        break;
                    }
                    if index >= references::MAX_EXTENT_INSTRUCTIONS {
                        stop = "instruction_limit";
                        break;
                    }
                    let Some(instruction) = program
                        .disassemble(current, 1)
                        .ok()
                        .and_then(|mut list| list.pop())
                    else {
                        stop = "decode_failure";
                        break;
                    };
                    if instruction.length == 0 {
                        stop = "decode_failure";
                        break;
                    }
                    if index >= input.offset {
                        if items.len() == input.limit {
                            return (items, false, "page");
                        }
                        let bytes: String = instruction
                            .bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect();
                        items.push(json!({
                            "address": address(instruction.address),
                            "length": instruction.length,
                            "bytes": bytes,
                            "mnemonic": instruction.mnemonic,
                            "operands": instruction.operands,
                        }));
                    }
                    index += 1;
                    current += instruction.length as u64;
                }
                (items, true, stop)
            })?;
        let next_offset = (!exhausted).then_some(input.offset + items.len());
        Ok(json!({
            "items": items,
            "offset": input.offset,
            "next_offset": next_offset,
            "stop": stop,
            "end": (end != u64::MAX).then(|| address(end)),
        }))
    }

    /// One structured, read-only instruction observation from the decoder and
    /// the instruction's first p-code translation.
    pub fn inspect_instruction(
        &mut self,
        input: crate::protocol::InspectInstructionParams,
    ) -> Result<Value> {
        let (bytes, _, _) = self.decompiler.verified_image()?;
        let mapped_ranges = image::mapped_ranges(&bytes)?;
        let starts = self.entry_addresses()?;
        let language = self.snapshot.language.clone();
        self.decompiler.with_program(&starts, |program, facts| {
            instruction::inspect(
                program,
                facts,
                &serde_json::json!({"address": input.address}),
                &language,
                &mapped_ranges,
            )
        })?
    }

    /// Recover decoded reachable ranges from direct control flow.
    pub fn function_body(&mut self, input: Value) -> Result<Value> {
        let requested = input
            .get("address")
            .and_then(Value::as_str)
            .context("function address is required")?;
        let entry = numeric(requested)?;
        let starts = self.entry_addresses()?;
        ensure!(
            starts.binary_search(&entry).is_ok(),
            "Address is absent from the saved inventory"
        );
        Ok(self.decompiler.with_program(&starts, |program, facts| {
            let result = walk_function_body(entry, &starts, |current| {
                decode_body_instruction(program, facts, current)
            });
            let merged = merge_ranges(result.ranges);
            let ranges_json = merged
                .iter()
                .map(|range| {
                    json!({
                        "start": address(range.start),
                        "end": address(range.end.saturating_sub(1))
                    })
                })
                .collect::<Vec<_>>();
            let total_bytes = merged
                .iter()
                .map(|range| range.end.saturating_sub(range.start))
                .sum::<u64>();
            json!({
                "address": requested,
                "complete": result.complete,
                "reason": result.reason,
                "basicblock_count": result.block_starts.len(),
                "ranges": ranges_json,
                "total_bytes": total_bytes
            })
        })?)
    }

    /// Bytes from file-backed sections, without loader fixups.
    pub fn read_bytes(&mut self, input: ByteRead) -> Result<Value> {
        ensure!(
            (1..=image::MAX_READ_BYTES).contains(&input.length),
            "Invalid byte read length"
        );
        let start = numeric(&input.address)?;
        let (bytes, _, file_offset) = self.decompiler.verified_image()?;
        if self.analysis.file_ranges.is_none() {
            self.analysis.file_ranges = Some(Arc::new(image::file_ranges(&bytes, file_offset)?));
        }
        let ranges = Arc::clone(
            self.analysis
                .file_ranges
                .as_ref()
                .expect("ranges were just read"),
        );
        let read = image::read(&bytes, &ranges, file_offset, start, input.length);
        let hex: String = read.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(json!({
            "address": input.address,
            "requested_bytes": input.length,
            "returned_bytes": read.len(),
            "bytes_hex": hex,
            "complete": read.len() == input.length,
        }))
    }
}

#[cfg(test)]
mod function_body_tests {
    use super::{
        BodyDecodeError, BodyInstruction, BranchTarget, direct_branch_target, merge_ranges,
        walk_function_body,
    };
    use ghidra_decompiler::opcodes::OpCode;
    use ghidra_decompiler::program::{PcodeOperation, PcodeVarnode};
    use std::ops::Range;

    #[test]
    fn merges_instruction_ranges_without_merging_cfg_gaps() {
        let ranges = merge_ranges(vec![
            Range {
                start: 0x1004,
                end: 0x1008,
            },
            Range {
                start: 0x1000,
                end: 0x1004,
            },
            Range {
                start: 0x2000,
                end: 0x2004,
            },
        ]);
        assert_eq!(
            ranges,
            vec![
                Range {
                    start: 0x1000,
                    end: 0x1008
                },
                Range {
                    start: 0x2000,
                    end: 0x2004
                },
            ]
        );
    }

    #[test]
    fn preserves_non_contiguous_branch_ranges() {
        let ranges = merge_ranges(vec![
            Range {
                start: 0x1000,
                end: 0x1004,
            },
            Range {
                start: 0x1010,
                end: 0x1014,
            },
        ]);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, 0x1000);
        assert_eq!(ranges[1].start, 0x1010);
    }

    #[test]
    fn merging_overlapping_ranges_keeps_the_full_extent() {
        assert_eq!(
            merge_ranges(vec![0x1000..0x1020, 0x1008..0x1010]),
            vec![0x1000..0x1020]
        );
    }

    #[test]
    fn only_ram_branch_operands_are_reachable_targets() {
        let direct = PcodeOperation {
            opcode: OpCode::Branch,
            output: None,
            inputs: vec![PcodeVarnode {
                space: "ram".to_owned(),
                offset: 0x2020,
                size: 8,
            }],
            space: None,
        };
        let computed = PcodeOperation {
            opcode: OpCode::Branchind,
            output: None,
            inputs: vec![PcodeVarnode {
                space: "register".to_owned(),
                offset: 0,
                size: 8,
            }],
            space: None,
        };
        assert_eq!(direct_branch_target(&direct), Some(0x2020));
        assert_eq!(direct_branch_target(&computed), None);
    }

    #[test]
    fn const_branch_operands_are_explicitly_internal() {
        let internal = PcodeOperation {
            opcode: OpCode::Branch,
            output: None,
            inputs: vec![PcodeVarnode {
                space: "const".to_owned(),
                offset: 0x10,
                size: 8,
            }],
            space: None,
        };
        assert_eq!(super::branch_target(&internal), BranchTarget::Internal);
    }

    fn walk(
        instructions: Vec<(u64, Result<Option<BodyInstruction>, BodyDecodeError>)>,
        starts: &[u64],
    ) -> super::FunctionBodyResult {
        walk_function_body(0x1000, starts, |address| {
            instructions
                .iter()
                .find(|(candidate, _)| *candidate == address)
                .map(|(_, result)| result.clone())
                .unwrap_or(Ok(None))
        })
    }

    #[test]
    fn follows_conditional_edges_and_terminates_loops() {
        let result = walk(
            vec![
                (
                    0x1000,
                    Ok(Some(BodyInstruction {
                        length: 4,
                        has_return: false,
                        unconditional: None,
                        conditional: Some(BranchTarget::Direct(0x1010)),
                        ambiguous_control: false,
                    })),
                ),
                (
                    0x1004,
                    Ok(Some(BodyInstruction {
                        length: 4,
                        has_return: false,
                        unconditional: Some(BranchTarget::Direct(0x1000)),
                        conditional: None,
                        ambiguous_control: false,
                    })),
                ),
                (
                    0x1010,
                    Ok(Some(BodyInstruction {
                        length: 4,
                        has_return: true,
                        unconditional: None,
                        conditional: None,
                        ambiguous_control: false,
                    })),
                ),
            ],
            &[0x1000],
        );
        assert!(result.complete);
        assert_eq!(result.block_starts.len(), 3);
        assert_eq!(result.ranges.len(), 3);
    }

    #[test]
    fn promotes_a_forward_target_inside_fallthrough_to_a_block_start() {
        let result = walk(
            vec![
                (
                    0x1000,
                    Ok(Some(BodyInstruction {
                        length: 4,
                        has_return: false,
                        unconditional: None,
                        conditional: Some(BranchTarget::Direct(0x1008)),
                        ambiguous_control: false,
                    })),
                ),
                (
                    0x1004,
                    Ok(Some(BodyInstruction {
                        length: 4,
                        has_return: false,
                        unconditional: None,
                        conditional: None,
                        ambiguous_control: false,
                    })),
                ),
                (
                    0x1008,
                    Ok(Some(BodyInstruction {
                        length: 4,
                        has_return: true,
                        unconditional: None,
                        conditional: None,
                        ambiguous_control: false,
                    })),
                ),
            ],
            &[0x1000],
        );
        assert!(result.complete);
        assert_eq!(result.block_starts.len(), 3);
        assert!(result.block_starts.contains(&0x1008));
    }

    #[test]
    fn does_not_include_another_inventory_function() {
        let result = walk(
            vec![(
                0x1000,
                Ok(Some(BodyInstruction {
                    length: 4,
                    has_return: false,
                    unconditional: Some(BranchTarget::Direct(0x2000)),
                    conditional: None,
                    ambiguous_control: false,
                })),
            )],
            &[0x1000, 0x2000],
        );
        assert!(!result.complete);
        assert_eq!(result.reason, "inventory-boundary");
        assert_eq!(result.ranges, vec![0x1000..0x1004]);
    }

    #[test]
    fn reports_unknown_decode_and_partial_branch_paths() {
        let decode_failure = walk(vec![(0x1000, Err(BodyDecodeError::Decode))], &[0x1000]);
        assert_eq!(decode_failure.reason, "decode-failure");
        assert!(decode_failure.block_starts.is_empty());

        let partial = walk(
            vec![
                (
                    0x1000,
                    Ok(Some(BodyInstruction {
                        length: 4,
                        has_return: false,
                        unconditional: None,
                        conditional: Some(BranchTarget::Direct(0x1010)),
                        ambiguous_control: false,
                    })),
                ),
                (
                    0x1004,
                    Ok(Some(BodyInstruction {
                        length: 4,
                        has_return: true,
                        unconditional: None,
                        conditional: None,
                        ambiguous_control: false,
                    })),
                ),
                (0x1010, Err(BodyDecodeError::Pcode)),
            ],
            &[0x1000],
        );
        assert_eq!(partial.reason, "pcode-failure");
        assert_eq!(partial.ranges, vec![0x1000..0x1004, 0x1004..0x1008]);
    }

    #[test]
    fn computed_control_flow_is_incomplete_but_fallthrough_is_preserved() {
        let result = walk(
            vec![
                (
                    0x1000,
                    Ok(Some(BodyInstruction {
                        length: 4,
                        has_return: false,
                        unconditional: None,
                        conditional: Some(BranchTarget::Computed),
                        ambiguous_control: false,
                    })),
                ),
                (
                    0x1004,
                    Ok(Some(BodyInstruction {
                        length: 4,
                        has_return: true,
                        unconditional: None,
                        conditional: None,
                        ambiguous_control: false,
                    })),
                ),
            ],
            &[0x1000],
        );
        assert!(!result.complete);
        assert_eq!(result.reason, "computed-branch");
        assert_eq!(result.block_starts.len(), 2);
    }

    #[test]
    fn internal_control_flow_is_incomplete_without_fabricating_a_target() {
        let result = walk(
            vec![(
                0x1000,
                Ok(Some(BodyInstruction {
                    length: 4,
                    has_return: false,
                    unconditional: Some(BranchTarget::Internal),
                    conditional: None,
                    ambiguous_control: false,
                })),
            )],
            &[0x1000],
        );
        assert!(!result.complete);
        assert_eq!(result.reason, "internal-branch");
        assert_eq!(result.block_starts.len(), 1);
    }

    #[test]
    fn mixed_terminal_operations_are_incomplete() {
        let result = walk(
            vec![(
                0x1000,
                Ok(Some(BodyInstruction {
                    length: 4,
                    has_return: true,
                    unconditional: None,
                    conditional: None,
                    ambiguous_control: true,
                })),
            )],
            &[0x1000],
        );
        assert!(!result.complete);
        assert_eq!(result.reason, "ambiguous-control");
        assert_eq!(result.ranges, vec![0x1000..0x1004]);
    }

    #[test]
    fn instruction_spanning_inventory_entry_is_incomplete() {
        let result = walk(
            vec![(
                0x1000,
                Ok(Some(BodyInstruction {
                    length: 8,
                    has_return: true,
                    unconditional: None,
                    conditional: None,
                    ambiguous_control: false,
                })),
            )],
            &[0x1000, 0x1004],
        );
        assert!(!result.complete);
        assert_eq!(result.reason, "inventory-boundary");
        assert!(result.ranges.is_empty());
    }

    #[test]
    fn conditional_fallthrough_cannot_cross_an_inventory_boundary() {
        let result = walk(
            vec![(
                0x1000,
                Ok(Some(BodyInstruction {
                    length: 4,
                    has_return: false,
                    unconditional: None,
                    conditional: Some(BranchTarget::Direct(0x1010)),
                    ambiguous_control: false,
                })),
            )],
            &[0x1000, 0x1004, 0x1010],
        );
        assert!(!result.complete);
        assert_eq!(result.reason, "inventory-boundary");
        assert_eq!(result.block_starts.len(), 1);
    }

    #[test]
    fn rejects_a_branch_into_a_decoded_instruction() {
        let result = walk(
            vec![(
                0x1000,
                Ok(Some(BodyInstruction {
                    length: 4,
                    has_return: false,
                    unconditional: Some(BranchTarget::Direct(0x1002)),
                    conditional: None,
                    ambiguous_control: false,
                })),
            )],
            &[0x1000],
        );
        assert_eq!(result.reason, "misaligned-target");
        assert!(!result.complete);
    }
}
