//! Strings, derived references, instruction listings and byte reads for the
//! admitted target.
pub(crate) mod image;
pub(crate) mod references;

use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::protocol::{address, parse_address};
use crate::session::Session;
use crate::target::load_program;
use crate::transport::Progress;
use image::ImageString;
use references::{Kind, Mapped, Reference};

/// Strings per `strings` page.
pub(crate) const MAX_STRING_PAGE: usize = 1024;
/// References per `references_to` / `references_from` page.
pub(crate) const MAX_REFERENCE_PAGE: usize = 4096;
/// Instructions per `instructions` page.
pub(crate) const MAX_INSTRUCTION_PAGE: usize = 4096;

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

fn numeric(text: &str) -> Result<u64> {
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
    fn image_strings(&mut self) -> Result<Arc<Vec<ImageString>>> {
        if self.analysis.strings.is_none() {
            let (bytes, _) = self.decompiler.verified_image()?;
            let strings = image::strings(&bytes)?;
            self.analysis.strings_sha256 = Some(strings_digest(&strings));
            self.analysis.strings = Some(Arc::new(strings));
        }
        Ok(Arc::clone(self.analysis.strings.as_ref().expect("strings were just read")))
    }

    /// One page of the string inventory.
    pub fn strings(&mut self, page: crate::protocol::PageParams) -> Result<Value> {
        ensure!(
            (1..=MAX_STRING_PAGE).contains(&page.limit),
            "Invalid string page size"
        );
        let strings = self.image_strings()?;
        ensure!(page.offset <= strings.len(), "Offset exceeds the string inventory");
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
        let (bytes, facts) = self.decompiler.verified_image()?;
        let mapped = Arc::new(Mapped::new(
            self.snapshot
                .segments
                .iter()
                .filter_map(|segment| Some(parse_address(&segment.address)?..parse_address(&segment.end)?))
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
                    let (bytes, facts, mapped, starts, path) =
                        (Arc::clone(&bytes), Arc::clone(&facts), Arc::clone(&mapped), Arc::clone(&starts), &path);
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
                                found.extend(references::sweep(&program, &facts, &mapped, &starts, entry));
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
    pub fn references_to(&mut self, input: AddressPage, progress: &mut impl Progress) -> Result<Value> {
        ensure!(
            (1..=MAX_REFERENCE_PAGE).contains(&input.limit),
            "Invalid reference page size"
        );
        let target = numeric(&input.address)?;
        self.ensure_references(progress)?;
        let (items, total) = self.cache.references_to(target, input.offset, input.limit)?;
        Ok(self.reference_page(&input, &items, total))
    }

    /// References from instructions of the inventory function at `address`.
    pub fn references_from(&mut self, input: AddressPage, progress: &mut impl Progress) -> Result<Value> {
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
        let (items, total) = self.cache.references_from(function, input.offset, input.limit)?;
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
        let (items, exhausted, stop) = self.decompiler.with_program(&starts, |program, facts| {
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
                let Some(instruction) = program.disassemble(current, 1).ok().and_then(|mut list| list.pop()) else {
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
                    let bytes: String = instruction.bytes.iter().map(|byte| format!("{byte:02x}")).collect();
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

    /// Bytes from file-backed sections, without loader fixups.
    pub fn read_bytes(&mut self, input: ByteRead) -> Result<Value> {
        ensure!(
            (1..=image::MAX_READ_BYTES).contains(&input.length),
            "Invalid byte read length"
        );
        let start = numeric(&input.address)?;
        let (bytes, _) = self.decompiler.verified_image()?;
        if self.analysis.file_ranges.is_none() {
            self.analysis.file_ranges = Some(Arc::new(image::file_ranges(&bytes)?));
        }
        let ranges = Arc::clone(self.analysis.file_ranges.as_ref().expect("ranges were just read"));
        let read = image::read(&bytes, &ranges, start, input.length);
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
