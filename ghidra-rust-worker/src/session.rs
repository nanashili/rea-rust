use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use crate::cache::{Cache, Snapshot};
use crate::configuration::{Configuration, validate_digest};
use crate::decompiler_pool::DecompilerPool;
use crate::inventory;
use crate::protocol::{MAX_NAME_BYTES, MAX_RESOLUTION_SELECTORS, OpenParams, PageParams, ResolveParams};
use crate::target::{TargetImage, load_program};
use crate::transport::Progress;

pub struct Session {
    pub cache: Cache,
    pub snapshot: Snapshot,
    pub(crate) decompiler: DecompilerPool,
    /// Sorted frozen entry addresses, read once for tail-call boundaries.
    entry_addresses: Option<std::sync::Arc<Vec<u64>>>,
    preparation: &'static str,
    pub(crate) analysis: crate::analysis::AnalysisState,
}

impl Session {
    pub fn open(
        configuration: &Configuration,
        input: OpenParams,
        progress: &mut impl Progress,
    ) -> Result<Self> {
        validate_digest(&input.target_sha256)?;
        ensure!(input.path.is_absolute(), "Target path must be absolute");
        let cache_path = configuration.cache_path(&input.target_sha256);
        let cache = Cache::open(&cache_path)?;
        sync_cache_directory(&configuration.cache_directory)?;

        if let Some(snapshot) = cache.snapshot()? {
            crate::target_file::verify(&input.path, &input.target_sha256)
                .context("Verify the target before restoring saved analysis")?;
            snapshot
                .validate(&configuration.identity, &input.target_sha256)
                .map_err(crate::failure::cache_integrity)?;
            return Self::restore(cache, snapshot, input, configuration.decompile_threads, progress);
        }

        Self::prepare_loader(cache, configuration, input, progress)
    }

    fn restore(
        cache: Cache,
        snapshot: Snapshot,
        input: OpenParams,
        threads: usize,
        progress: &mut impl Progress,
    ) -> Result<Self> {
        progress.report("Checking saved inventory commitment", 0, None)?;
        cache.validate_inventory_metadata(&snapshot)?;
        let decompiler = pool(&snapshot, input.path, threads);
        Ok(Self {
            cache,
            snapshot,
            decompiler,
            entry_addresses: None,
            preparation: "restored",
            analysis: Default::default(),
        })
    }

    fn prepare_loader(
        cache: Cache,
        configuration: &Configuration,
        input: OpenParams,
        progress: &mut impl Progress,
    ) -> Result<Self> {
        progress.report("Reading loader inventory", 0, None)?;
        let image = TargetImage::read(&input.path, &input.target_sha256)?;
        let code_ranges = image.code_ranges.clone();
        let program = load_program(&input.path, image.bytes)?;
        let frozen = inventory::freeze(&program, image.metadata_functions, image.arm, &code_ranges)?;
        let functions = frozen.functions;
        let aliases = frozen.aliases;
        let snapshot = Snapshot {
            config_identity: configuration.identity.clone(),
            target_sha256: input.target_sha256,
            inventory_sha256: frozen.inventory_sha256,
            inventory_indexes_sha256: None,
            indexed_functions: functions.len(),
            aliases_sha256: frozen.aliases_sha256,
            indexed_aliases: aliases.len(),
            language: program.language_id().to_owned(),
            arm: image.arm,
            segments: image.sections,
        };
        // Loader admission only needs the frozen rows and language after this point.
        drop(program);
        snapshot.validate(&configuration.identity, &snapshot.target_sha256)?;
        progress.report(
            "Saving frozen inventory",
            functions.len(),
            Some(functions.len()),
        )?;
        let snapshot = cache.install(&snapshot, &functions, &aliases)?;
        let decompiler = pool(&snapshot, input.path, configuration.decompile_threads);
        Ok(Self {
            cache,
            snapshot,
            decompiler,
            entry_addresses: None,
            preparation: "loader_inventory",
            analysis: Default::default(),
        })
    }

    pub fn prepared_info(&self) -> Value {
        json!({
            "target_sha256": self.snapshot.target_sha256,
            "inventory_sha256": self.snapshot.inventory_sha256,
            "indexed_functions": self.snapshot.indexed_functions,
            "total": self.snapshot.indexed_functions,
            "preparation": self.preparation,
            "language": self.snapshot.language,
            "limitations": crate::metadata::limitations()
        })
    }

    pub fn functions(&self, page: PageParams) -> Result<Value> {
        let items = self.cache.page(&self.snapshot, &page)?;
        let next = page.offset + items.len();
        Ok(json!({
            "items": items,
            "offset": page.offset,
            "next_offset": (next < self.snapshot.indexed_functions).then_some(next),
            "indexed_functions": self.snapshot.indexed_functions,
            "total": self.snapshot.indexed_functions,
            "inventory_sha256": self.snapshot.inventory_sha256
        }))
    }

    /// One page of additional loader symbols, ordered by address then name.
    pub fn aliases(&self, page: PageParams) -> Result<Value> {
        let items = self.cache.alias_page(&self.snapshot, &page)?;
        let next = page.offset + items.len();
        Ok(json!({
            "items": items,
            "offset": page.offset,
            "next_offset": (next < self.snapshot.indexed_aliases).then_some(next),
            "total": self.snapshot.indexed_aliases,
            "aliases_sha256": self.snapshot.aliases_sha256,
            "inventory_sha256": self.snapshot.inventory_sha256
        }))
    }

    pub fn segments(&self) -> Value {
        json!({
            "items": self.snapshot.segments,
            "coverage": "Object section ranges; executable means a text section. Complete runtime memory permissions are unknown."
        })
    }

    pub fn resolve(&self, input: ResolveParams) -> Result<Value> {
        ensure!(
            input.selectors.len() <= MAX_RESOLUTION_SELECTORS,
            "At most 64 selectors are accepted"
        );
        let mut items = Vec::with_capacity(input.selectors.len());
        for selector in input.selectors {
            ensure!(
                selector.len() <= MAX_NAME_BYTES,
                "Selector exceeds 4096 UTF-8 bytes"
            );
            items.push(self.cache.resolve(&self.snapshot, &selector)?);
        }
        Ok(json!({ "items": items, "inventory_sha256": self.snapshot.inventory_sha256 }))
    }

    pub(crate) fn entry_addresses(&mut self) -> Result<std::sync::Arc<Vec<u64>>> {
        if self.entry_addresses.is_none() {
            let entries = self.cache.entry_addresses(&self.snapshot)?;
            self.entry_addresses = Some(std::sync::Arc::new(entries));
        }
        Ok(std::sync::Arc::clone(
            self.entry_addresses.as_ref().expect("entry addresses were just read"),
        ))
    }

    pub(crate) fn time_until_program_idle_release(&self, now: Instant) -> Option<Duration> {
        self.decompiler.time_until_idle_release(now)
    }

    pub(crate) fn release_program_at_safe_point(&mut self, now: Instant) {
        self.decompiler.release_at_safe_point(now);
    }

    pub(crate) fn discard_program(&mut self) {
        self.decompiler.discard();
    }
}

fn pool(snapshot: &Snapshot, path: PathBuf, threads: usize) -> DecompilerPool {
    DecompilerPool::new(
        path,
        snapshot.target_sha256.clone(),
        snapshot.language.clone(),
        threads,
    )
}

#[cfg(unix)]
fn sync_cache_directory(path: &std::path::Path) -> Result<()> {
    std::fs::File::open(path)?
        .sync_all()
        .context("Persist the new cache directory entry")
}

#[cfg(not(unix))]
fn sync_cache_directory(_path: &std::path::Path) -> Result<()> {
    // redb guarantees committed file contents; std has no portable directory fsync.
    Ok(())
}
