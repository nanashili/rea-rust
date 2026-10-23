use std::cell::{Cell, RefCell};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use redb::{
    Database, DatabaseError, Durability, ReadableDatabase, StorageError, TableDefinition,
    TableError, WriteTransaction,
};

use crate::configuration::{hash_bytes, validate_digest};
use crate::encoding::encode_bounded;
use crate::protocol::{DATABASE_CACHE_BYTES, Function, FunctionAlias, MAX_FRAME_BYTES};

mod references;
mod results;
mod snapshot;

pub(crate) use references::ReferenceManifest;

pub use snapshot::Snapshot;

pub(crate) const META: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata-v1");
pub(crate) const INVENTORY: TableDefinition<u64, &[u8]> = TableDefinition::new("inventory-v1");
pub(crate) const ADDRESSES: TableDefinition<u64, u64> = TableDefinition::new("addresses-v1");
pub(crate) const NAMES: TableDefinition<&str, &str> = TableDefinition::new("names-v1");
pub(crate) const ALIASES: TableDefinition<u64, &[u8]> = TableDefinition::new("aliases-v1");
const RESULTS: TableDefinition<u64, &[u8]> = TableDefinition::new("pseudocode-v1");

pub struct Cache {
    pub(crate) database: Database,
    pub(crate) inventory_integrity: RefCell<Option<crate::cache_inventory::InventoryIntegrity>>,
    failed_commit: Cell<bool>,
}

impl Cache {
    pub fn open(path: &Path) -> Result<Self> {
        let database = Database::builder()
            .set_cache_size(DATABASE_CACHE_BYTES)
            .create(path)
            .map_err(classify_open_error)
            .with_context(|| format!("Open saved state at {}", path.display()))
            .context("Open the exclusive saved-state database")?;
        Ok(Self {
            database,
            inventory_integrity: RefCell::new(None),
            failed_commit: Cell::new(false),
        })
    }

    pub fn snapshot(&self) -> Result<Option<Snapshot>> {
        self.read_snapshot()
            .map_err(crate::failure::cache_integrity)
    }

    fn read_snapshot(&self) -> Result<Option<Snapshot>> {
        let transaction = self.database.begin_read()?;
        let table = match transaction.open_table(META) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };

        let Some(value) = table.get("snapshot")? else {
            return Ok(None);
        };
        ensure!(
            value.value().len() < MAX_FRAME_BYTES,
            "Saved metadata exceeds the limit"
        );
        let digest = table
            .get("snapshot_sha256")?
            .context("Saved metadata has no checksum")?;
        let digest = std::str::from_utf8(digest.value()).context("Invalid metadata checksum")?;
        validate_digest(digest)?;
        ensure!(
            hash_bytes(value.value()) == digest,
            "Saved metadata checksum differs"
        );
        serde_json::from_slice(value.value())
            .context("Decode saved metadata")
            .map(Some)
    }

    pub fn install(
        &self,
        snapshot: &Snapshot,
        functions: &[Function],
        aliases: &[FunctionAlias],
    ) -> Result<Snapshot> {
        self.inventory_integrity.borrow_mut().take();
        let committed =
            self.write_durable("Atomically save the frozen inventory", |transaction| {
                crate::cache_inventory::install(transaction, functions, aliases)?;
                let mut snapshot = snapshot.clone();
                snapshot.inventory_indexes_sha256 = Some(
                    crate::cache_inventory::install_commitment(transaction, &snapshot)?,
                );
                transaction.open_table(RESULTS)?;
                store_snapshot(transaction, &snapshot)?;
                Ok(snapshot)
            })?;
        self.validate_inventory_metadata(&committed)?;
        Ok(committed)
    }

    pub fn validate_inventory_metadata(&self, snapshot: &Snapshot) -> Result<()> {
        self.load_inventory_metadata(snapshot)
            .map_err(crate::failure::cache_integrity)
    }

    fn load_inventory_metadata(&self, snapshot: &Snapshot) -> Result<()> {
        self.inventory_integrity.borrow_mut().take();
        let upgraded;
        let snapshot = if snapshot.inventory_indexes_sha256.is_none() {
            upgraded = self.write_durable(
                "Verify and upgrade the saved inventory commitment",
                |transaction| {
                    let mut snapshot = snapshot.clone();
                    snapshot.inventory_indexes_sha256 = Some(
                        crate::cache_inventory::upgrade_commitment(transaction, &snapshot)?,
                    );
                    store_snapshot(transaction, &snapshot)?;
                    Ok(snapshot)
                },
            )?;
            &upgraded
        } else {
            snapshot
        };
        let transaction = self.database.begin_read()?;
        transaction.open_table(RESULTS)?;
        let integrity = crate::cache_inventory::load_commitment(&transaction, snapshot)?;
        self.inventory_integrity.replace(Some(integrity));
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<()> {
        ensure!(
            !self.failed_commit.get(),
            "Cache durability is uncertain; restart the worker"
        );
        // Every writer commits with Immediate durability before returning. This
        // acknowledgment must not issue a second commit or fsync for the same work.
        self.snapshot()?
            .context("No frozen inventory has been committed")?;
        Ok(())
    }

    fn write_durable<T>(
        &self,
        context: &'static str,
        write: impl FnOnce(&WriteTransaction) -> Result<T>,
    ) -> Result<T> {
        ensure!(
            !self.failed_commit.get(),
            "Cache durability is uncertain; restart the worker"
        );
        let mut transaction = self.database.begin_write().context(context)?;
        let prepared = (|| {
            transaction.set_durability(Durability::Immediate)?;
            write(&transaction)
        })();

        let value = match prepared {
            Ok(value) => value,
            Err(original) => {
                return match transaction.abort() {
                    Ok(()) => Err(original.context(context)),
                    Err(rollback) => {
                        self.failed_commit.set(true);
                        Err(original
                            .context(format!("{context}; rollback also failed: {rollback}")))
                    }
                };
            }
        };

        transaction.commit().map_err(|error| {
            self.failed_commit.set(true);
            anyhow::Error::from(error).context(context)
        })?;
        Ok(value)
    }
}

fn classify_open_error(error: DatabaseError) -> anyhow::Error {
    match error {
        DatabaseError::UpgradeRequired(_)
        | DatabaseError::RepairAborted
        | DatabaseError::Storage(StorageError::Corrupted(_)) => {
            crate::failure::cache_integrity(error)
        }
        _ => error.into(),
    }
}

fn store_snapshot(transaction: &WriteTransaction, snapshot: &Snapshot) -> Result<()> {
    let encoded = encode_bounded(snapshot, MAX_FRAME_BYTES - 1)?;
    let digest = hash_bytes(&encoded);
    let mut metadata = transaction.open_table(META)?;
    metadata.insert("snapshot", encoded.as_slice())?;
    metadata.insert("snapshot_sha256", digest.as_bytes())?;
    Ok(())
}
