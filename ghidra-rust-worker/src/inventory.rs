use std::ops::Range;

use anyhow::{Result, ensure};
use ghidra_decompiler::program::Program;
use sha2::{Digest, Sha256};

use crate::protocol::{
    Function, FunctionAlias, MAX_INVENTORY, MAX_INVENTORY_NAME_BYTES, MAX_NAME_BYTES, address,
};

struct InventoryEntry {
    address: u64,
    name: String,
    loader_symbol: bool,
}

/// The frozen inventory: one row per entry address plus every additional
/// loader symbol that names one of those entries.
pub struct FrozenInventory {
    pub functions: Vec<Function>,
    pub inventory_sha256: String,
    pub aliases: Vec<FunctionAlias>,
    pub aliases_sha256: String,
}

/// Freeze loader function symbols in executable sections and function-start
/// metadata. Loader symbols outside executable sections (for example the
/// Mach-O `__mh_execute_header` marker) do not identify code and are excluded.
pub fn freeze(
    program: &Program,
    metadata_functions: Vec<u64>,
    arm: bool,
    code_ranges: &[Range<u64>],
) -> Result<FrozenInventory> {
    let mut entries = loader_entries(program, arm, code_ranges)?;
    extend_metadata(&mut entries, metadata_functions, arm)?;
    entries.sort_unstable_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| right.loader_symbol.cmp(&left.loader_symbol))
            .then_with(|| left.name.cmp(&right.name))
    });

    let mut hash = new_inventory_hash();
    let mut alias_hash = new_alias_hash();
    let mut functions: Vec<Function> = Vec::new();
    let mut aliases = Vec::new();
    let mut primary: Option<(u64, String)> = None;
    for entry in entries {
        match &primary {
            Some((current, name)) if *current == entry.address => {
                // Sorting places loader symbols before synthesized metadata
                // names and orders names within an address, so a later entry
                // is an alias only when the loader reported it, and an exact
                // repeat of the previous name carries nothing new.
                let repeated = entry.name == *name
                    || aliases.last().is_some_and(|previous: &FunctionAlias| {
                        previous.address == address(*current) && previous.name == entry.name
                    });
                if entry.loader_symbol && !repeated {
                    update_alias_hash(&mut alias_hash, entry.address, &entry.name);
                    aliases.push(FunctionAlias {
                        address: address(entry.address),
                        name: entry.name,
                    });
                }
            }
            _ => {
                update_inventory_hash(&mut hash, entry.address, &entry.name);
                functions.push(Function {
                    address: address(entry.address),
                    name: entry.name.clone(),
                });
                primary = Some((entry.address, entry.name));
            }
        }
    }
    Ok(FrozenInventory {
        functions,
        inventory_sha256: finish_inventory_hash(hash),
        aliases,
        aliases_sha256: finish_inventory_hash(alias_hash),
    })
}

fn loader_entries(
    program: &Program,
    arm: bool,
    code_ranges: &[Range<u64>],
) -> Result<Vec<InventoryEntry>> {
    let functions = program.functions()?;
    ensure!(
        functions.len() <= MAX_INVENTORY,
        "Loader inventory exceeds the limit"
    );
    let mut entries = Vec::with_capacity(functions.len());
    let mut name_bytes = 0_usize;
    for function in functions {
        let entry = normalize(function.address, arm);
        if !code_ranges.iter().any(|range| range.contains(&entry)) {
            continue;
        }
        name_bytes = admit_name(name_bytes, &function.name)?;
        entries.push(InventoryEntry {
            address: entry,
            name: function.name,
            loader_symbol: true,
        });
    }
    Ok(entries)
}

fn extend_metadata(
    entries: &mut Vec<InventoryEntry>,
    metadata_functions: Vec<u64>,
    arm: bool,
) -> Result<()> {
    let mut name_bytes = entries.iter().map(|entry| entry.name.len()).sum();
    for value in metadata_functions {
        ensure!(
            entries.len() < MAX_INVENTORY,
            "Combined loader inventory exceeds the limit"
        );
        let value = normalize(value, arm);
        let name = format!("FUN_{value:x}");
        name_bytes = admit_name(name_bytes, &name)?;
        entries.push(InventoryEntry {
            address: value,
            name,
            loader_symbol: false,
        });
    }
    Ok(())
}

fn admit_name(previous_bytes: usize, name: &str) -> Result<usize> {
    ensure!(
        name.len() <= MAX_NAME_BYTES,
        "Function name exceeds the protocol limit"
    );
    let total = previous_bytes + name.len();
    ensure!(
        total <= MAX_INVENTORY_NAME_BYTES,
        "Loader function names exceed the 32 MiB budget"
    );
    Ok(total)
}

pub(crate) fn new_inventory_hash() -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(b"rea-rust-ghidra-inventory-v1\0");
    hash
}

pub(crate) fn update_inventory_hash(hash: &mut Sha256, address: u64, name: &str) {
    hash.update(address.to_be_bytes());
    hash.update((name.len() as u64).to_be_bytes());
    hash.update(name.as_bytes());
}

pub(crate) fn new_alias_hash() -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(b"rea-rust-ghidra-aliases-v1\0");
    hash
}

/// Alias rows use the inventory row encoding under a distinct domain.
pub(crate) fn update_alias_hash(hash: &mut Sha256, address: u64, name: &str) {
    update_inventory_hash(hash, address, name);
}

pub(crate) fn finish_inventory_hash(hash: Sha256) -> String {
    format!("{:x}", hash.finalize())
}

fn normalize(value: u64, arm: bool) -> u64 {
    if arm { value & !1 } else { value }
}
