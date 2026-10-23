//! Validated paging of the frozen function inventory.
//!
//! Compatibility owners: `src/ghidra-rust/GhidraRustInventory.ts` and
//! `GhidraRustInventorySnapshot.ts`.
use crate::protocol::{
    MAX_ALIAS_PAGE, MAX_FUNCTION_PAGE, MAX_INVENTORY_FUNCTIONS, MAX_INVENTORY_NAME_BYTES,
    Procedure, parse_alias_page, parse_function_page,
};
use crate::session::Session;
use crate::worker::Control;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

/// `GhidraRustInventoryBuilder`: admit sorted procedures before committing
/// one digest-checked snapshot.
///
/// The snapshot is bounded by the worker's own frozen-inventory contract
/// (`MAX_INVENTORY_FUNCTIONS` rows and `MAX_INVENTORY_NAME_BYTES` of names),
/// which the worker enforces before it publishes a commitment. A page that
/// exceeds either bound is a protocol violation, not a caller-visible
/// capacity limit. Transport-sized delivery belongs to the MCP adapter, which
/// pages retained inventory Evidence.
struct Builder<'a> {
    session: &'a Session,
    procedures: Vec<Procedure>,
    digest: Sha256,
    name_bytes: usize,
    previous: Option<u64>,
}

impl<'a> Builder<'a> {
    fn new(session: &'a Session, total: u64) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"rea-rust-ghidra-inventory-v1\0");
        Self {
            session,
            // `total` was validated against MAX_INVENTORY_FUNCTIONS by `read`.
            procedures: Vec::with_capacity(total as usize),
            digest,
            name_bytes: 0,
            previous: None,
        }
    }

    fn append(&mut self, items: Vec<Procedure>) -> Result<(), AnalysisError> {
        for item in items {
            let coordinate = u64::from_str_radix(&item.address[2..], 16).unwrap_or(0);
            if self.previous.is_some_and(|previous| coordinate <= previous) {
                return Err(self
                    .session
                    .failure("The worker inventory is not sorted and unique."));
            }
            self.name_bytes += item.name.len();
            if self.name_bytes > MAX_INVENTORY_NAME_BYTES {
                return Err(self
                    .session
                    .failure("The worker inventory exceeds its published function-name budget."));
            }
            self.previous = Some(coordinate);
            self.digest.update(coordinate.to_be_bytes());
            self.digest.update((item.name.len() as u64).to_be_bytes());
            self.digest.update(item.name.as_bytes());
            self.procedures.push(item);
        }
        Ok(())
    }

    fn finish(self, expected: &str) -> Result<Vec<Procedure>, AnalysisError> {
        if format!("{:x}", self.digest.finalize()) != expected {
            return Err(self
                .session
                .failure("The enumerated inventory differs from its SHA-256 commitment."));
        }
        Ok(self.procedures)
    }
}

/// `GhidraRustInventory`: read and cache validated pages.
#[derive(Default)]
pub(crate) struct Inventory {
    snapshot: Mutex<Option<Arc<Vec<Procedure>>>>,
    /// Additional loader names, read only when a name search needs them.
    aliases: Mutex<Option<Arc<Vec<Procedure>>>>,
}

impl Inventory {
    /// `list`: `{ address, value }` per procedure.
    pub(crate) fn list(
        &self,
        session: &Session,
        control: &Control,
    ) -> Result<Value, AnalysisError> {
        let procedures = self.read(session, control)?;
        Ok(Value::Array(
            procedures
                .iter()
                .map(|procedure| json!({ "address": procedure.address, "value": procedure.name }))
                .collect(),
        ))
    }

    /// `read`: the complete frozen inventory.
    pub(crate) fn read(
        &self,
        session: &Session,
        control: &Control,
    ) -> Result<Arc<Vec<Procedure>>, AnalysisError> {
        let ready = session.prepare(control)?;
        if let Some(snapshot) = self
            .snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            return Ok(snapshot);
        }
        let total = match ready.total {
            Some(total) if total <= MAX_INVENTORY_FUNCTIONS => total,
            _ => {
                return Err(session.failure(
                    "The worker inventory count is missing or exceeds its published function limit.",
                ));
            }
        };
        let mut builder = Builder::new(session, total);
        let mut offset = 0_u64;
        loop {
            let reply = session.worker.request(
                "functions",
                json!({ "offset": offset, "limit": MAX_FUNCTION_PAGE }),
                Some(control),
            )?;
            let page = parse_function_page(&reply).map_err(|_| {
                session.failure("The Rust worker returned an invalid procedure page.")
            })?;
            let next = offset + page.items.len() as u64;
            if page.offset != offset
                || Some(&page.inventory_sha256) != ready.inventory_sha256.as_ref()
                || Some(page.total) != ready.total
                || page.indexed_functions != page.total
                || next > page.total
                || page.next_offset != (next < page.total).then_some(next)
                || (next < page.total && page.items.is_empty())
            {
                return Err(session.failure(
                    "Procedure paging differs from the frozen inventory or complete count.",
                ));
            }
            let following = page.next_offset;
            builder.append(page.items)?;
            match following {
                None => break,
                Some(next) => offset = next,
            }
        }
        let procedures =
            Arc::new(builder.finish(ready.inventory_sha256.as_deref().unwrap_or_default())?);
        *self
            .snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::clone(&procedures));
        Ok(procedures)
    }

    /// `search`: literal saved-inventory name matches.
    pub(crate) fn search(
        &self,
        session: &Session,
        input: &Map<String, Value>,
        control: &Control,
    ) -> Result<Value, AnalysisError> {
        if input.get("mode").and_then(Value::as_str) != Some("literal") {
            return Err(AnalysisError::input_message(
                "search_procedures",
                "The saved Rust inventory supports literal name searches only.",
                Vec::new(),
            ));
        }
        let procedures = self.read(session, control)?;
        let aliases = self.read_aliases(session, &procedures, control)?;
        let case_sensitive = input.get("case_sensitive") == Some(&Value::Bool(true));
        let pattern = input
            .get("pattern")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let pattern = if case_sensitive {
            pattern.to_owned()
        } else {
            pattern.to_lowercase()
        };
        let matches = |name: &str| {
            if case_sensitive {
                name.contains(&pattern)
            } else {
                name.to_lowercase().contains(&pattern)
            }
        };
        // Results stay in address order; at one entry the primary name
        // precedes its aliases, which the worker orders by name.
        let mut results = Vec::new();
        let mut alias = aliases.iter().peekable();
        for procedure in procedures.iter() {
            if matches(&procedure.name) {
                results.push(json!({ "address": procedure.address, "value": procedure.name }));
            }
            while let Some(entry) = alias.next_if(|entry| entry.address == procedure.address) {
                if matches(&entry.name) {
                    results.push(json!({ "address": entry.address, "value": entry.name }));
                }
            }
        }
        Ok(Value::Array(results))
    }

    /// `function_aliases`: every additional loader name at a frozen entry,
    /// validated page by page against its commitment.
    fn read_aliases(
        &self,
        session: &Session,
        procedures: &[Procedure],
        control: &Control,
    ) -> Result<Arc<Vec<Procedure>>, AnalysisError> {
        if let Some(aliases) = self
            .aliases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            return Ok(aliases);
        }
        let ready = session.prepare(control)?;
        let invalid =
            || session.failure("Alias paging differs from the frozen inventory or its commitment.");
        let primary_bytes: usize = procedures
            .iter()
            .map(|procedure| procedure.name.len())
            .sum();
        let mut name_bytes = primary_bytes;
        let mut digest = Sha256::new();
        digest.update(b"rea-rust-ghidra-aliases-v1\0");
        let mut aliases: Vec<Procedure> = Vec::new();
        let mut expected: Option<(u64, String)> = None;
        let mut previous: Option<(u64, String)> = None;
        let mut entry = 0_usize;
        let mut offset = 0_u64;
        loop {
            let reply = session.worker.request(
                "function_aliases",
                json!({ "offset": offset, "limit": MAX_ALIAS_PAGE }),
                Some(control),
            )?;
            let page = parse_alias_page(&reply)
                .map_err(|_| session.failure("The Rust worker returned an invalid alias page."))?;
            let next = offset + page.items.len() as u64;
            let facts = (page.total, page.aliases_sha256.clone());
            if page.offset != offset
                || Some(&page.inventory_sha256) != ready.inventory_sha256.as_ref()
                || expected.as_ref().is_some_and(|known| *known != facts)
                || page.total > MAX_INVENTORY_FUNCTIONS - procedures.len() as u64
                || next > page.total
                || page.next_offset != (next < page.total).then_some(next)
                || (next < page.total && page.items.is_empty())
            {
                return Err(invalid());
            }
            expected = Some(facts);
            let following = page.next_offset;
            for alias in page.items {
                let coordinate = u64::from_str_radix(&alias.address[2..], 16).unwrap_or(0);
                if previous.as_ref().is_some_and(|(address, name)| {
                    (*address, name.as_str()) >= (coordinate, alias.name.as_str())
                }) {
                    return Err(invalid());
                }
                // Aliases follow the sorted inventory; each names an entry
                // under a name other than that entry's primary name.
                while procedures
                    .get(entry)
                    .is_some_and(|procedure| procedure.address != alias.address)
                {
                    entry += 1;
                }
                if procedures
                    .get(entry)
                    .is_none_or(|procedure| procedure.name == alias.name)
                {
                    return Err(invalid());
                }
                name_bytes += alias.name.len();
                if name_bytes > MAX_INVENTORY_NAME_BYTES {
                    return Err(session
                        .failure("The worker aliases exceed the published function-name budget."));
                }
                digest.update(coordinate.to_be_bytes());
                digest.update((alias.name.len() as u64).to_be_bytes());
                digest.update(alias.name.as_bytes());
                previous = Some((coordinate, alias.name.clone()));
                aliases.push(alias);
            }
            match following {
                None => break,
                Some(next) => offset = next,
            }
        }
        let Some((total, committed)) = expected else {
            return Err(invalid());
        };
        if aliases.len() as u64 != total || format!("{:x}", digest.finalize()) != committed {
            return Err(invalid());
        }
        let aliases = Arc::new(aliases);
        *self
            .aliases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::clone(&aliases));
        Ok(aliases)
    }
}
