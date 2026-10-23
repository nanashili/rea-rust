use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use crate::protocol::{
    BatchItem, BatchParams, Function, MAX_BATCH_SIZE, MAX_PSEUDOCODE_BYTES, PageParams, address,
    parse_address,
};
use crate::decompiler_pool::Outcome;
use crate::session::Session;
use crate::transport::Progress;

#[path = "batch_output.rs"]
mod output;

use output::BatchOutput;

const PROGRESS_CHECKPOINT_INTERVAL: usize = 16;

#[derive(Clone, Copy)]
enum BatchMode {
    DecompileMissing,
    CacheOnly,
}

impl Session {
    pub fn batch(
        &mut self,
        input: BatchParams,
        timeout_ms: u64,
        progress: &mut impl Progress,
    ) -> Result<Value> {
        ensure!(
            input.addresses.len() <= MAX_BATCH_SIZE,
            "At most 1024 addresses are accepted"
        );
        let mut functions = Vec::with_capacity(input.addresses.len());
        for selected in input.addresses {
            let numeric_address =
                parse_address(&selected).context("Expected a canonical address")?;
            ensure!(
                address(numeric_address) == selected,
                "Expected a canonical address"
            );
            let function = self
                .cache
                .function(numeric_address)?
                .context("Address is absent from the saved inventory")?;
            functions.push(function);
        }

        let mode = if input.cache_only {
            BatchMode::CacheOnly
        } else {
            BatchMode::DecompileMissing
        };
        self.execute_batch(functions, mode, timeout_ms, progress)
    }

    pub fn inventory_batch(
        &mut self,
        page: PageParams,
        timeout_ms: u64,
        progress: &mut impl Progress,
    ) -> Result<Value> {
        ensure!(
            page.limit <= MAX_BATCH_SIZE,
            "At most 1024 inventory items are accepted"
        );
        ensure!(page.limit >= 1, "Invalid inventory batch size");
        ensure!(
            page.offset <= self.snapshot.indexed_functions,
            "Offset exceeds the saved inventory"
        );
        // A decompile page may span several inventory read pages.
        let end = (page.offset + page.limit).min(self.snapshot.indexed_functions);
        let mut functions = Vec::with_capacity(end - page.offset);
        let mut offset = page.offset;
        while offset < end {
            let limit = (end - offset).min(crate::protocol::MAX_FUNCTION_PAGE);
            let read = self.cache.page(&self.snapshot, &PageParams { offset, limit })?;
            if read.is_empty() {
                break;
            }
            offset += read.len();
            functions.extend(read);
        }
        let mut reply =
            self.execute_batch(functions, BatchMode::DecompileMissing, timeout_ms, progress)?;
        let completed = reply["completed"]
            .as_u64()
            .context("Missing native batch completion count")? as usize;
        let next = page.offset + completed;
        reply["offset"] = json!(page.offset);
        reply["next_offset"] = json!((next < self.snapshot.indexed_functions).then_some(next));
        reply["indexed_functions"] = json!(self.snapshot.indexed_functions);
        Ok(reply)
    }

    fn execute_batch(
        &mut self,
        functions: Vec<Function>,
        mode: BatchMode,
        timeout_ms: u64,
        progress: &mut impl Progress,
    ) -> Result<Value> {
        let mut output = BatchOutput::new(&functions)?;
        let result = self.run_batch(&functions, mode, timeout_ms, progress, &mut output);
        match result {
            Ok(()) => Ok(output.into_reply(&self.snapshot.inventory_sha256)),
            Err(error) => {
                self.discard_program();
                let error = match output.checkpoint(&self.cache) {
                    Ok(()) => error,
                    Err(checkpoint_error) => error.context(format!(
                        "Checkpoint partial batch results before returning: {checkpoint_error:#}"
                    )),
                };
                output.into_partial(&self.snapshot.inventory_sha256, error)
            }
        }
    }

    fn run_batch(
        &mut self,
        functions: &[Function],
        mode: BatchMode,
        timeout_ms: u64,
        progress: &mut impl Progress,
        output: &mut BatchOutput,
    ) -> Result<()> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let progress_label = match mode {
            BatchMode::DecompileMissing => "Decompiling frozen inventory",
            BatchMode::CacheOnly => "Reading persisted pseudocode",
        };

        // Saved results and cache-only misses are resolved here; uncached
        // functions are decompiled on the pool and delivered in input order.
        let mut ready: Vec<Option<(BatchItem, bool)>> = vec![None; functions.len()];
        let mut jobs = Vec::new();
        for (index, function) in functions.iter().enumerate() {
            let numeric_address =
                parse_address(&function.address).context("Invalid frozen address")?;
            if let Some(cached) = self.cache.result(numeric_address, function)? {
                ready[index] = Some((cached, false));
            } else if matches!(mode, BatchMode::CacheOnly) {
                ready[index] = Some((
                    BatchItem::failure(
                        function,
                        "CACHE_MISS",
                        "No validated persisted pseudocode is available for this saved address.",
                    ),
                    false,
                ));
            } else {
                // This address came from the verified frozen inventory. The
                // engine may define this requested symbol when loader metadata
                // omitted it; the worker does not enqueue other functions.
                jobs.push((index, numeric_address));
            }
        }

        let mut recorder = OrderedRecorder {
            functions,
            ready,
            next: 0,
            label: progress_label,
        };
        recorder.drain(&self.cache, output, progress)?;
        if !jobs.is_empty() {
            progress
                .report("Loading decompilers for uncached saved functions", 0, None)
                .context("Report decompiler preparation")?;
            let starts = self.entry_addresses()?;
            let cache = &self.cache;
            self.decompiler
                .decompile(&jobs, &starts, deadline, |index, outcome| {
                    let function = &functions[index];
                    let item = match outcome {
                        Outcome::Decompiled(result) => decompiled_item(function, result),
                        Outcome::Deadline => deadline_item(
                            function,
                            "The request deadline elapsed before this function began.",
                        ),
                    };
                    let fresh = item.pseudocode.is_some();
                    recorder.ready[index] = Some((item, fresh));
                    recorder.drain(cache, output, progress)
                })
                .context("Run the decompiler for saved functions")?;
        }
        ensure!(
            recorder.next == functions.len(),
            "The decompiler did not return every selected function"
        );

        if functions.is_empty() {
            output.checkpoint(&self.cache)?;
        }

        Ok(())
    }
}

/// Records completed items strictly in input order, with the original
/// checkpoint and progress cadence.
struct OrderedRecorder<'a> {
    functions: &'a [Function],
    ready: Vec<Option<(BatchItem, bool)>>,
    next: usize,
    label: &'static str,
}

impl OrderedRecorder<'_> {
    fn drain(
        &mut self,
        cache: &crate::cache::Cache,
        output: &mut BatchOutput,
        progress: &mut impl Progress,
    ) -> Result<()> {
        while let Some((item, fresh)) = self.ready.get_mut(self.next).and_then(Option::take) {
            output.record(cache, &self.functions[self.next], item, fresh)?;
            self.next += 1;
            let completed = self.next;
            if completed.is_multiple_of(PROGRESS_CHECKPOINT_INTERVAL) || completed == self.functions.len() {
                output.checkpoint(cache)?;
                progress
                    .report(self.label, completed, Some(self.functions.len()))
                    .context("Report completed batch progress")?;
            }
        }
        Ok(())
    }
}

fn decompiled_item(
    function: &Function,
    result: ghidra_decompiler::error::Result<String>,
) -> BatchItem {
    match result {
        Ok(code) if code.trim().is_empty() => BatchItem::failure(
            function,
            "DECOMPILE_FAILED",
            "The engine returned empty pseudocode.",
        ),
        Ok(code) if code.len() > MAX_PSEUDOCODE_BYTES => BatchItem::failure(
            function,
            "OUTPUT_LIMIT",
            "Pseudocode exceeds 512 KiB of UTF-8. No truncated result was saved.",
        ),
        Ok(code) => BatchItem::success(function, code),
        Err(error) => BatchItem::failure(function, "DECOMPILE_FAILED", error.explain()),
    }
}

fn deadline_item(function: &Function, message: &str) -> BatchItem {
    BatchItem::failure(function, "REQUEST_DEADLINE", message)
}
