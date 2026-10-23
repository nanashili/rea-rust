//! Validation and bounded retention for the worker's frozen function index.
//!
//! The worker owns function discovery.  This module owns the host-side rules
//! for admitting pages, preserving their order, and checking the inventory
//! commitment before exposing it to an application consumer.

use sha2::{Digest, Sha256};

use crate::ghidra_rust::protocol::{MAX_FUNCTION_PAGE, WorkerFunction, WorkerFunctionPage};

pub const MAX_INVENTORY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_INVENTORY_FUNCTIONS: usize = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Procedure {
    pub address: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventorySnapshot {
    pub procedures: Vec<Procedure>,
}

pub struct InventoryBuilder {
    procedures: Vec<Procedure>,
    digest: Sha256,
    previous_address: Option<u64>,
    retained_bytes: usize,
}

impl Default for InventoryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl InventoryBuilder {
    pub fn new() -> Self {
        let mut digest = Sha256::new();
        digest.update(b"rea-rust-ghidra-inventory-v1\0");
        Self {
            procedures: Vec::new(),
            digest,
            previous_address: None,
            retained_bytes: 2,
        }
    }

    pub fn append(
        &mut self,
        page: &WorkerFunctionPage,
        expected_offset: usize,
        expected_inventory: &str,
        expected_total: usize,
    ) -> Result<Option<usize>, String> {
        validate_page(page, expected_offset, expected_inventory, expected_total)?;

        for item in &page.items {
            self.append_item(item, expected_total)?;
        }

        Ok(page.next_offset)
    }

    pub fn finish(self, expected_digest: &str) -> Result<InventorySnapshot, String> {
        validate_digest(expected_digest)?;
        let actual = format!("{:x}", self.digest.finalize());
        if actual != expected_digest {
            return Err("the enumerated inventory differs from its SHA-256 commitment".into());
        }
        Ok(InventorySnapshot {
            procedures: self.procedures,
        })
    }

    fn append_item(&mut self, item: &WorkerFunction, total: usize) -> Result<(), String> {
        let address = parse_address(&item.address)?;
        if self
            .previous_address
            .is_some_and(|previous| address <= previous)
        {
            return Err("the worker inventory is not sorted and unique".into());
        }

        let serialized_projection_bytes = serialized_projection_bytes(item)?;
        if self
            .retained_bytes
            .saturating_add(serialized_projection_bytes)
            > MAX_INVENTORY_BYTES
        {
            return Err(format!(
                "the complete procedure map exceeds the {MAX_INVENTORY_BYTES}-byte retained budget ({total} indexed functions)"
            ));
        }

        self.retained_bytes += serialized_projection_bytes;
        self.previous_address = Some(address);
        self.digest.update(address.to_be_bytes());
        self.digest
            .update((item.name.len() as u64).to_be_bytes());
        self.digest.update(item.name.as_bytes());
        self.procedures.push(Procedure {
            address: item.address.clone(),
            name: item.name.clone(),
        });
        Ok(())
    }
}

pub fn validate_page(
    page: &WorkerFunctionPage,
    expected_offset: usize,
    expected_inventory: &str,
    expected_total: usize,
) -> Result<(), String> {
    if page.items.len() > MAX_FUNCTION_PAGE {
        return Err("function page exceeds its item limit".into());
    }

    validate_count(expected_offset, "expected function page offset")?;
    validate_count(page.offset, "function page offset")?;
    validate_optional_count(page.next_offset, "function page continuation")?;
    validate_count(page.indexed_functions, "indexed function count")?;
    validate_count(page.total, "total function count")?;

    if page.offset != expected_offset
        || page.inventory_sha256 != expected_inventory
        || page.total != expected_total
        || page.indexed_functions != page.total
    {
        return Err("procedure paging differs from the frozen inventory or complete count".into());
    }

    let next = expected_offset
        .checked_add(page.items.len())
        .ok_or_else(|| "procedure page offset overflowed".to_owned())?;
    let expected_next = (next < page.total).then_some(next);
    if next > page.total || page.next_offset != expected_next {
        return Err("procedure page continuation differs from the complete count".into());
    }
    if next < page.total && page.items.is_empty() {
        return Err("procedure paging made no progress".into());
    }
    Ok(())
}

fn validate_count(value: usize, label: &str) -> Result<(), String> {
    if value > MAX_INVENTORY_FUNCTIONS {
        return Err(format!("{label} exceeds the one-million function limit"));
    }
    Ok(())
}

fn validate_optional_count(value: Option<usize>, label: &str) -> Result<(), String> {
    if let Some(value) = value {
        validate_count(value, label)?;
    }
    Ok(())
}

fn parse_address(value: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| "worker address must use a lowercase 0x prefix".to_owned())?;
    if digits.is_empty()
        || digits.len() > 16
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return Err("worker address is outside the bounded hexadecimal range".into());
    }
    u64::from_str_radix(digits, 16).map_err(|_| "worker address is not a valid integer".into())
}

fn serialized_projection_bytes(item: &WorkerFunction) -> Result<usize, String> {
    let projection = serde_json::json!({
        "address": item.address,
        "value": item.name,
    });
    let serialized = serde_json::to_vec(&projection)
        .map_err(|error| format!("procedure projection could not be serialized: {error}"))?;
    serialized
        .len()
        .checked_add(1)
        .ok_or_else(|| "procedure projection size overflowed".to_owned())
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("inventory commitment must be a lowercase SHA-256 digest".into());
    }
    Ok(())
}
