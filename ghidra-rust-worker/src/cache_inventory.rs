mod build;
mod commitment;
mod manifest;
mod read_rows;
mod verify_names;
mod verify_rows;

pub(crate) use commitment::InventoryIntegrity;
pub(crate) use manifest::load as load_commitment;

use anyhow::{Context, Result, ensure};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, Table, WriteTransaction};
use serde_json::{Value, json};

use crate::cache::{ADDRESSES, ALIASES, Cache, INVENTORY, NAMES, Snapshot};
use crate::inventory::{finish_inventory_hash, new_alias_hash, update_alias_hash};
use crate::protocol::{
    Function, FunctionAlias, MAX_ALIAS_PAGE, MAX_FUNCTION_PAGE, MAX_NAME_BYTES, PageParams,
    address, parse_address,
};

pub fn install(
    transaction: &WriteTransaction,
    functions: &[Function],
    aliases: &[FunctionAlias],
) -> Result<()> {
    let mut inventory = transaction.open_table(INVENTORY)?;
    let mut addresses = transaction.open_table(ADDRESSES)?;
    let mut names = transaction.open_table(NAMES)?;
    let mut alias_rows = transaction.open_table(ALIASES)?;
    ensure!(
        inventory.is_empty()?
            && addresses.is_empty()?
            && names.is_empty()?
            && alias_rows.is_empty()?,
        "A frozen inventory is already installed"
    );

    for (ordinal, function) in functions.iter().enumerate() {
        let numeric_address = parse_address(&function.address).context("Invalid frozen address")?;
        let encoded = serde_json::to_vec(function)?;
        inventory.insert(ordinal as u64, encoded.as_slice())?;
        addresses.insert(numeric_address, ordinal as u64)?;

        index_name(&mut names, &function.name, &function.address)?;
    }
    for (ordinal, alias) in aliases.iter().enumerate() {
        let numeric_address = parse_address(&alias.address).context("Invalid frozen alias")?;
        ensure!(
            addresses.get(numeric_address)?.is_some(),
            "A frozen alias names no inventory entry"
        );
        let encoded = serde_json::to_vec(alias)?;
        alias_rows.insert(ordinal as u64, encoded.as_slice())?;
        // Selector resolution accepts every name of an entry; one name at two
        // entries stays ambiguous exactly like two primary names.
        index_name(&mut names, &alias.name, &alias.address)?;
    }

    Ok(())
}

/// Index every saved alias name; used to rebuild the expected name index.
pub(super) fn index_aliases(
    transaction: &WriteTransaction,
    names: &mut Table<'_, &str, &str>,
) -> Result<()> {
    let aliases = transaction.open_table(ALIASES)?;
    for entry in aliases.iter()? {
        let (_, value) = entry?;
        let alias = decode_alias(value.value())?;
        index_name(names, &alias.name, &alias.address)?;
    }
    Ok(())
}

pub(crate) fn install_commitment(
    transaction: &WriteTransaction,
    snapshot: &Snapshot,
) -> Result<String> {
    build::install(transaction, snapshot)
}

pub(crate) fn upgrade_commitment(
    transaction: &WriteTransaction,
    snapshot: &Snapshot,
) -> Result<String> {
    build::upgrade(transaction, snapshot)
}

fn index_name(names: &mut Table<'_, &str, &str>, name: &str, function_address: &str) -> Result<()> {
    let previous = names.get(name)?.map(|value| value.value().to_owned());
    let resolution = match previous {
        Some(previous) if previous != function_address => "",
        _ => function_address,
    };
    names.insert(name, resolution)?;
    Ok(())
}

impl Cache {
    pub fn function(&self, numeric_address: u64) -> Result<Option<Function>> {
        self.read_function(numeric_address)
            .map_err(crate::failure::cache_integrity)
    }

    fn read_function(&self, numeric_address: u64) -> Result<Option<Function>> {
        let transaction = self.database.begin_read()?;
        let Some(committed_rows) = self.verify_function_chunk(&transaction, numeric_address)?
        else {
            return Ok(None);
        };
        let addresses = transaction.open_table(ADDRESSES)?;
        let Some(ordinal) = addresses.get(numeric_address)? else {
            return Ok(None);
        };
        ensure!(
            committed_rows.contains(&ordinal.value()),
            "Address index leaves its committed chunk"
        );

        let inventory = transaction.open_table(INVENTORY)?;
        let value = inventory
            .get(ordinal.value())?
            .context("Incomplete saved inventory")?;
        let function = decode_function(value.value())?;
        ensure!(
            parse_address(&function.address) == Some(numeric_address),
            "Invalid address index"
        );
        Ok(Some(function))
    }

    /// Every frozen entry address in ascending order, from the address index.
    pub fn entry_addresses(&self, snapshot: &Snapshot) -> Result<Vec<u64>> {
        self.read_entry_addresses(snapshot)
            .map_err(crate::failure::cache_integrity)
    }

    fn read_entry_addresses(&self, snapshot: &Snapshot) -> Result<Vec<u64>> {
        let transaction = self.database.begin_read()?;
        let addresses = transaction.open_table(ADDRESSES)?;
        let mut entries = Vec::with_capacity(snapshot.indexed_functions);
        for entry in addresses.iter()? {
            let (address, _) = entry?;
            entries.push(address.value());
        }
        ensure!(
            entries.len() == snapshot.indexed_functions,
            "Saved address index count differs"
        );
        Ok(entries)
    }

    pub fn page(&self, snapshot: &Snapshot, page: &PageParams) -> Result<Vec<Function>> {
        ensure!(
            page.offset <= snapshot.indexed_functions,
            "Offset exceeds the saved inventory"
        );
        ensure!(
            (1..=MAX_FUNCTION_PAGE).contains(&page.limit),
            "Invalid function page size"
        );
        self.read_page(snapshot, page)
            .map_err(crate::failure::cache_integrity)
    }

    fn read_page(&self, snapshot: &Snapshot, page: &PageParams) -> Result<Vec<Function>> {
        let end = (page.offset + page.limit).min(snapshot.indexed_functions);
        let transaction = self.database.begin_read()?;
        self.verify_page_chunks(&transaction, page.offset, end)?;
        let inventory = transaction.open_table(INVENTORY)?;
        let addresses = transaction.open_table(ADDRESSES)?;
        let mut functions = Vec::with_capacity(end - page.offset);

        for ordinal in page.offset..end {
            let value = inventory
                .get(ordinal as u64)?
                .context("Incomplete saved inventory")?;
            let function = decode_function(value.value())?;
            let numeric_address =
                parse_address(&function.address).context("Invalid saved inventory address")?;
            let indexed_ordinal = addresses
                .get(numeric_address)?
                .context("Saved address index is missing a function")?;
            ensure!(
                indexed_ordinal.value() == ordinal as u64,
                "Saved address index does not point to its inventory row"
            );
            functions.push(function);
        }
        Ok(functions)
    }

    pub fn resolve(&self, snapshot: &Snapshot, selector: &str) -> Result<Value> {
        self.read_resolution(snapshot, selector)
            .map_err(crate::failure::cache_integrity)
    }

    fn read_resolution(&self, snapshot: &Snapshot, selector: &str) -> Result<Value> {
        if let Some(numeric_address) = selector_address(selector, snapshot.arm) {
            return Ok(resolution(selector, self.function(numeric_address)?, false));
        }

        let transaction = self.database.begin_read()?;
        let Some(saved) = self.verified_name(&transaction, selector)? else {
            return Ok(resolution(selector, None, false));
        };
        if saved.is_empty() {
            return Ok(resolution(selector, None, true));
        }

        let numeric_address = parse_address(&saved).context("Invalid saved name index")?;
        let function = self
            .function(numeric_address)?
            .context("Incomplete saved name index")?;
        // The selector is the entry's primary name or one of its aliases. The
        // name index chunk was authenticated above, and the resolution
        // reports the entry's canonical address and primary name.
        Ok(resolution(selector, Some(function), false))
    }

    /// One validated page of saved aliases. The complete alias table is
    /// verified against the snapshot commitment on first use.
    pub fn alias_page(&self, snapshot: &Snapshot, page: &PageParams) -> Result<Vec<FunctionAlias>> {
        ensure!(
            page.offset <= snapshot.indexed_aliases,
            "Offset exceeds the saved aliases"
        );
        ensure!(
            (1..=MAX_ALIAS_PAGE).contains(&page.limit),
            "Invalid alias page size"
        );
        self.read_alias_page(snapshot, page)
            .map_err(crate::failure::cache_integrity)
    }

    fn read_alias_page(&self, snapshot: &Snapshot, page: &PageParams) -> Result<Vec<FunctionAlias>> {
        let transaction = self.database.begin_read()?;
        let aliases = transaction.open_table(ALIASES)?;
        let addresses = transaction.open_table(ADDRESSES)?;
        self.verify_aliases(snapshot, &aliases, &addresses)?;
        let end = (page.offset + page.limit).min(snapshot.indexed_aliases);
        let mut items = Vec::with_capacity(end - page.offset);
        for ordinal in page.offset..end {
            let value = aliases
                .get(ordinal as u64)?
                .context("Incomplete saved aliases")?;
            items.push(decode_alias(value.value())?);
        }
        Ok(items)
    }

    fn verify_aliases(
        &self,
        snapshot: &Snapshot,
        aliases: &impl ReadableTable<u64, &'static [u8]>,
        addresses: &impl ReadableTable<u64, u64>,
    ) -> Result<()> {
        let mut integrity = self.inventory_integrity.borrow_mut();
        let integrity = integrity
            .as_mut()
            .context("Inventory commitment is not loaded")?;
        if integrity.verified_aliases {
            return Ok(());
        }
        ensure!(
            aliases.len()? == snapshot.indexed_aliases as u64,
            "Saved alias count differs"
        );
        let mut hash = new_alias_hash();
        let mut previous: Option<(u64, String)> = None;
        for (expected, entry) in aliases.iter()?.enumerate() {
            let (ordinal, value) = entry?;
            ensure!(ordinal.value() == expected as u64, "Saved alias ordinal differs");
            let alias = decode_alias(value.value())?;
            let numeric_address = parse_address(&alias.address).context("Invalid saved alias")?;
            ensure!(
                previous
                    .as_ref()
                    .is_none_or(|(address, name)| (*address, name.as_str()) < (numeric_address, alias.name.as_str())),
                "Saved aliases are not strictly ordered"
            );
            ensure!(
                addresses.get(numeric_address)?.is_some(),
                "A saved alias names no inventory entry"
            );
            update_alias_hash(&mut hash, numeric_address, &alias.name);
            previous = Some((numeric_address, alias.name));
        }
        ensure!(
            finish_inventory_hash(hash) == snapshot.aliases_sha256,
            "Saved alias commitment differs"
        );
        integrity.verified_aliases = true;
        Ok(())
    }
}

pub(crate) fn decode_alias(bytes: &[u8]) -> Result<FunctionAlias> {
    ensure!(
        bytes.len() <= 6 * MAX_NAME_BYTES + 128,
        "Invalid alias record size"
    );
    let alias: FunctionAlias = serde_json::from_slice(bytes)?;
    let numeric_address = parse_address(&alias.address).context("Invalid saved alias address")?;
    ensure!(
        address(numeric_address) == alias.address,
        "Noncanonical saved alias address"
    );
    ensure!(
        !alias.name.is_empty() && alias.name.len() <= MAX_NAME_BYTES,
        "Invalid saved alias name"
    );
    Ok(alias)
}

pub fn selector_address(selector: &str, arm: bool) -> Option<u64> {
    let normalized_prefix;
    let selector = if let Some(hex) = selector.strip_prefix("0X") {
        normalized_prefix = format!("0x{hex}");
        normalized_prefix.as_str()
    } else {
        selector
    };
    parse_address(selector).map(|value| if arm { value & !1 } else { value })
}

pub(crate) fn decode_function(bytes: &[u8]) -> Result<Function> {
    ensure!(
        bytes.len() <= 6 * MAX_NAME_BYTES + 128,
        "Invalid inventory record size"
    );
    let function: Function = serde_json::from_slice(bytes)?;
    let numeric_address = parse_address(&function.address).context("Invalid saved address")?;
    ensure!(
        address(numeric_address) == function.address,
        "Noncanonical saved address"
    );
    ensure!(
        function.name.len() <= MAX_NAME_BYTES,
        "Invalid saved function name"
    );
    Ok(function)
}

fn resolution(selector: &str, function: Option<Function>, ambiguous: bool) -> Value {
    let status = if ambiguous {
        "ambiguous"
    } else if function.is_some() {
        "found"
    } else {
        "not_found"
    };
    json!({
        "selector": selector,
        "status": status,
        "address": function.as_ref().map(|f| f.address.as_str()),
        "name": function.as_ref().map(|f| f.name.as_str())
    })
}
