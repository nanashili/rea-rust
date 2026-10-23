//! Inventory-backed orchestration for bounded Rust-Ghidra batches.
//!
//! The worker and application layers own different parts of this workflow.
//! This module owns the ordering and retry policy between them: selectors are
//! resolved in bounded pages, duplicate procedures retain every selector
//! index, native batches are capped, and only validated output-limit rows use
//! cache-only retrieval.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{
    ghidra_rust::batch_plan::{IndexedSelector, SelectedProcedure, SelectorPages},
    ghidra_rust::batch_reply::{BatchItem, BatchReply, BatchReplyError},
    ghidra_rust::protocol::WorkerFunctionResolution,
};

pub const MAX_RETAINED_BATCH_BYTES: usize = 32 * 1024 * 1024;

/// Options which affect execution without changing selector order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchOptions {
    pub operation: BatchOperation,
    pub cache_only: bool,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            operation: BatchOperation::BatchDecompile,
            cache_only: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchOperation {
    BatchDecompile,
    ProcedurePseudoCode,
}

impl BatchOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BatchDecompile => "batch_decompile",
            Self::ProcedurePseudoCode => "procedure_pseudo_code",
        }
    }
}

/// A caller-visible item with the original selector preserved as its address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchResultItem {
    pub selector: String,
    pub procedure: Option<ResolvedProcedure>,
    pub pseudocode: Option<String>,
    pub error: Option<BatchItemFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProcedure {
    pub address: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchItemFailure {
    pub code: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhidraRustBatchResult {
    pub items: Vec<BatchResultItem>,
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub confirmed_addresses: Vec<String>,
    pub unconfirmed_addresses: Vec<String>,
}

/// The host-facing operations needed by the batch policy.
///
/// Implementations retain provider ownership and decide how a failed worker
/// is invalidated.  The orchestration layer therefore cannot accidentally
/// reopen a worker or turn an uncertain result into a retry.
pub trait GhidraRustBatchSession {
    type Error;

    fn inventory_sha256(&self) -> Option<&str>;
    fn resolve_page(
        &mut self,
        selectors: &[String],
        options: BatchOptions,
    ) -> Result<Vec<WorkerFunctionResolution>, Self::Error>;
    fn request_batch(
        &mut self,
        procedures: &[SelectedProcedure],
        options: BatchOptions,
    ) -> Result<Value, Self::Error>;
    fn acknowledge_checkpoint(&mut self) -> Result<(), Self::Error>;
    fn invalidate(&mut self);
    fn retain_partial_result(&mut self, result: Value);
    fn retain_rejected_batch(&mut self, reply: Value);
}

/// Resolve and execute all selectors while retaining partial facts on error.
pub fn execute_ghidra_rust_batch<S: GhidraRustBatchSession>(
    session: &mut S,
    selectors: &[String],
    options: BatchOptions,
) -> Result<GhidraRustBatchResult, BatchExecutionError<S::Error>> {
    if options.cache_only && session.inventory_sha256().is_none() {
        return Err(BatchExecutionError::Protocol(
            "cache-only retrieval requires an already prepared worker session".into(),
        ));
    }

    let mut accumulator = BatchAccumulator::new(selectors);
    let result = execute_pages(session, selectors, options, &mut accumulator);
    match result {
        Ok(()) => match accumulator.finish() {
            Ok(result) => Ok(result),
            Err(error) => {
                let failure = BatchExecutionError::Protocol(error);
                if accumulator.has_partial_result() {
                    session.retain_partial_result(accumulator.partial_value());
                }
                Err(failure)
            }
        },
        Err(error) => {
            if accumulator.has_partial_result() {
                // The session owns the Evidence/error representation.  The
                // accumulator remains available to that owner for inspection.
                session.retain_partial_result(accumulator.partial_value());
            }
            Err(error)
        }
    }
}

fn execute_pages<S: GhidraRustBatchSession>(
    session: &mut S,
    selectors: &[String],
    options: BatchOptions,
    accumulator: &mut BatchAccumulator<'_>,
) -> Result<(), BatchExecutionError<S::Error>> {
    for page in SelectorPages::new(selectors) {
        let requested = page
            .iter()
            .map(|item| item.selector.clone())
            .collect::<Vec<_>>();
        let resolved = session
            .resolve_page(&requested, options)
            .map_err(BatchExecutionError::Session)?;
        let selected = select_page::<S::Error>(&page, &resolved, accumulator)?;

        for chunk in selected.chunks(crate::ghidra_rust::protocol::MAX_BATCH_SIZE) {
            execute_native_batch(session, accumulator, chunk, options)?;
        }
    }
    Ok(())
}

fn select_page<E>(
    page: &[IndexedSelector],
    resolved: &[WorkerFunctionResolution],
    accumulator: &mut BatchAccumulator<'_>,
) -> Result<Vec<SelectedProcedure>, BatchExecutionError<E>> {
    let mut selected = Vec::new();
    for (page_index, result) in resolved.iter().enumerate() {
        let requested = page.get(page_index).ok_or_else(|| {
            BatchExecutionError::Protocol("the worker returned an extra selector result".into())
        })?;

        if result.selector != requested.selector {
            return Err(BatchExecutionError::Protocol(
                "selector resolution differs from the request".into(),
            ));
        }

        if result.status != "found" {
            if result.address.is_some() || result.name.is_some() {
                return Err(BatchExecutionError::Protocol(
                    "unresolved selector results must omit address and name".into(),
                ));
            }
            accumulator.record_failure(
                requested.index,
                BatchItemFailure {
                    code: Some(result.status.clone()),
                    message: selector_failure_message(&result.status),
                },
            )?;
            continue;
        }

        let address = result.address.clone().ok_or_else(|| {
            BatchExecutionError::Protocol("a resolved function lacks its address".into())
        })?;
        let name = result.name.clone().ok_or_else(|| {
            BatchExecutionError::Protocol("a resolved function lacks its name".into())
        })?;

        if let Some(existing) = selected
            .iter_mut()
            .find(|item: &&mut SelectedProcedure| item.address == address)
        {
            existing.indices.push(requested.index);
        } else {
            selected.push(SelectedProcedure {
                address,
                name,
                indices: vec![requested.index],
            });
        }
    }

    if resolved.len() != page.len() {
        return Err(BatchExecutionError::Protocol(
            "the worker returned an unexpected selector result count".into(),
        ));
    }

    Ok(selected)
}

fn selector_failure_message(status: &str) -> String {
    if status == "ambiguous" {
        "The function name is ambiguous; select an inventory address.".into()
    } else {
        "The selector is outside the frozen function inventory.".into()
    }
}

fn execute_native_batch<S: GhidraRustBatchSession>(
    session: &mut S,
    accumulator: &mut BatchAccumulator<'_>,
    procedures: &[SelectedProcedure],
    options: BatchOptions,
) -> Result<(), BatchExecutionError<S::Error>> {
    let value = session
        .request_batch(procedures, options)
        .map_err(BatchExecutionError::Session)?;
    let reply = match BatchReply::parse(&value) {
        Ok(reply) => reply,
        Err(error) => {
            accumulator.retain_rejected_batch(value.clone());
            session.retain_rejected_batch(value);
            session.invalidate();
            return Err(BatchExecutionError::Reply(error));
        }
    };

    let inventory = session.inventory_sha256().ok_or_else(|| {
        BatchExecutionError::Protocol("batch execution requires a frozen inventory".into())
    })?;
    let expected = procedures
        .iter()
        .map(|procedure| (procedure.address.clone(), procedure.name.clone()))
        .collect::<Vec<_>>();
    if let Err(error) = reply.validate(inventory, &expected) {
        accumulator.retain_rejected_batch(value.clone());
        session.retain_rejected_batch(value);
        session.invalidate();
        return Err(BatchExecutionError::Reply(error));
    }

    // Keep the validated frame available before projecting any facts.  A
    // later budget, indexing, or acknowledgement error must still retain the
    // source receipt together with the facts already accumulated from it.
    accumulator.retain_rejected_batch(value.clone());
    session.retain_rejected_batch(value.clone());
    accumulator.record_durability(&reply)?;

    record_reply::<S>(accumulator, procedures, &reply)?;

    if reply.failure.is_none() {
        session
            .acknowledge_checkpoint()
            .map_err(BatchExecutionError::Session)?;
    }

    if let Some(failure) = reply.failure {
        session.invalidate();
        return Err(BatchExecutionError::Worker(BatchWorkerFailure {
            wire_code: failure.error_code.clone(),
            error_code: failure.error_code,
            cause_code: failure.cause_code,
            message: failure.error_message,
            raw_frame: value,
        }));
    }

    if let Some(cache_miss) = reply
        .items
        .iter()
        .find(|item| item.error_code.as_deref() == Some("CACHE_MISS"))
    {
        return Err(BatchExecutionError::CacheMiss(
            cache_miss.error_message.clone().unwrap_or_else(|| {
                "The requested procedure is not present in the worker cache.".into()
            }),
        ));
    }

    retrieve_output_limited(session, accumulator, procedures, &reply, options)
}

fn record_reply<S: GhidraRustBatchSession>(
    accumulator: &mut BatchAccumulator<'_>,
    procedures: &[SelectedProcedure],
    reply: &BatchReply,
) -> Result<(), BatchExecutionError<S::Error>> {
    for (index, item) in reply.items.iter().enumerate() {
        let selection = procedures.get(index).ok_or_else(|| {
            BatchExecutionError::Protocol("a validated batch lost its selection".into())
        })?;
        if item.error_code.as_deref() == Some("BATCH_OUTPUT_LIMIT")
            && (procedures.len() > 1 || reply.failure.is_some())
        {
            continue;
        }
        let procedure = ResolvedProcedure {
            address: selection.address.clone(),
            name: selection.name.clone(),
        };
        for input_index in &selection.indices {
            let selector = accumulator
                .selectors
                .get(*input_index)
                .ok_or_else(|| {
                    BatchExecutionError::Protocol("invalid batch selector index".into())
                })?
                .clone();
            let result_item = if let Some(pseudocode) = item.pseudocode.clone() {
                BatchResultItem {
                    selector,
                    procedure: Some(procedure.clone()),
                    pseudocode: Some(pseudocode),
                    error: None,
                }
            } else {
                BatchResultItem {
                    selector,
                    procedure: Some(procedure.clone()),
                    pseudocode: None,
                    error: Some(item_failure(item)),
                }
            };
            accumulator.record_item(*input_index, result_item)?;
        }
    }
    Ok(())
}

fn item_failure(item: &BatchItem) -> BatchItemFailure {
    BatchItemFailure {
        code: item.error_code.clone(),
        message: item
            .error_message
            .clone()
            .unwrap_or_else(|| "The worker returned no pseudocode.".into()),
    }
}

fn retrieve_output_limited<S: GhidraRustBatchSession>(
    session: &mut S,
    accumulator: &mut BatchAccumulator<'_>,
    procedures: &[SelectedProcedure],
    reply: &BatchReply,
    options: BatchOptions,
) -> Result<(), BatchExecutionError<S::Error>> {
    if procedures.len() <= 1 {
        return Ok(());
    }
    let pending = procedures
        .iter()
        .enumerate()
        .filter_map(|(index, procedure)| {
            (reply.items[index].error_code.as_deref() == Some("BATCH_OUTPUT_LIMIT"))
                .then_some(procedure.clone())
        })
        .collect::<Vec<_>>();
    let group_size = procedures.len().div_ceil(2);
    let cache_options = BatchOptions {
        cache_only: true,
        ..options
    };
    for group in pending.chunks(group_size) {
        execute_native_batch(session, accumulator, group, cache_options)?;
    }
    Ok(())
}

#[derive(Debug)]
pub enum BatchExecutionError<E> {
    Session(E),
    Reply(BatchReplyError),
    Worker(BatchWorkerFailure),
    CacheMiss(String),
    Protocol(String),
    OutputBudget,
}

/// Structured identity for a worker failure carried by a validated batch.
///
/// The wire code identifies the batch failure envelope.  The error and cause
/// codes remain separate so callers can classify the worker failure without
/// reparsing the retained frame.  The raw frame preserves the exact evidence
/// that also contains the completed prefix and durability receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchWorkerFailure {
    pub wire_code: String,
    pub error_code: String,
    pub cause_code: String,
    pub message: String,
    pub raw_frame: Value,
}

impl<E: std::fmt::Display> std::fmt::Display for BatchExecutionError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session(error) => error.fmt(formatter),
            Self::Reply(error) => error.fmt(formatter),
            Self::Worker(BatchWorkerFailure { message, .. })
            | Self::CacheMiss(message)
            | Self::Protocol(message) => formatter.write_str(message),
            Self::OutputBudget => {
                formatter.write_str("the normalized batch exceeds its output budget")
            }
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for BatchExecutionError<E> {}

struct BatchAccumulator<'a> {
    selectors: &'a [String],
    items: Vec<Option<BatchResultItem>>,
    durability: BTreeMap<String, bool>,
    rejected_native_batch: Option<Value>,
    bytes: usize,
}

impl<'a> BatchAccumulator<'a> {
    fn new(selectors: &'a [String]) -> Self {
        Self {
            selectors,
            items: vec![None; selectors.len()],
            durability: BTreeMap::new(),
            rejected_native_batch: None,
            bytes: 256,
        }
    }

    fn retain_rejected_batch(&mut self, reply: Value) {
        self.rejected_native_batch = Some(reply);
    }

    fn record_failure<E>(
        &mut self,
        index: usize,
        error: BatchItemFailure,
    ) -> Result<(), BatchExecutionError<E>> {
        let selector = self
            .selectors
            .get(index)
            .ok_or_else(|| BatchExecutionError::Protocol("invalid batch result index".into()))?;
        self.record_item(
            index,
            BatchResultItem {
                selector: selector.clone(),
                procedure: None,
                pseudocode: None,
                error: Some(error),
            },
        )
    }

    fn record_item<E>(
        &mut self,
        index: usize,
        item: BatchResultItem,
    ) -> Result<(), BatchExecutionError<E>> {
        if self.items.get(index).is_none() {
            return Err(BatchExecutionError::Protocol(
                "invalid batch selector index".into(),
            ));
        }
        if self.items[index].is_some() {
            return Err(BatchExecutionError::Protocol(
                "a batch result slot was completed more than once".into(),
            ));
        }
        let item_bytes = serde_json::to_vec(&serde_json::json!({
            "input_index": index,
            "address": item.selector,
            "procedure": item.procedure.as_ref().map(|procedure| serde_json::json!({
                "status": "resolved",
                "address": procedure.address,
                "name": procedure.name,
            })).unwrap_or_else(|| serde_json::json!({ "status": "unknown" })),
            "status": if item.error.is_some() { "error" } else { "ok" },
            "pseudocode": item.pseudocode,
            "error": item.error.as_ref().map(|error| serde_json::json!({
                "code": error.code,
                "message": error.message,
            })),
        }))
        .map(|bytes| bytes.len() + 1)
        .unwrap_or(usize::MAX);
        if self.bytes.saturating_add(item_bytes) > MAX_RETAINED_BATCH_BYTES {
            return Err(BatchExecutionError::OutputBudget);
        }
        self.bytes += item_bytes;
        self.items[index] = Some(item);
        Ok(())
    }

    fn record_durability<E>(&mut self, reply: &BatchReply) -> Result<(), BatchExecutionError<E>> {
        for address in &reply.durability.confirmed_addresses {
            if let Some(address) = address {
                self.reserve_address::<E>(address)?;
                self.durability.insert(address.clone(), true);
            }
        }
        for address in &reply.durability.unconfirmed_addresses {
            if let Some(address) = address {
                self.reserve_address::<E>(address)?;
                self.durability.insert(address.clone(), false);
            }
        }
        Ok(())
    }

    fn reserve_address<E>(&mut self, address: &str) -> Result<(), BatchExecutionError<E>> {
        if self.durability.contains_key(address) {
            return Ok(());
        }
        let bytes = serde_json::to_vec(address)
            .map(|encoded| encoded.len() + 1)
            .unwrap_or(usize::MAX);
        if self.bytes.saturating_add(bytes) > MAX_RETAINED_BATCH_BYTES {
            return Err(BatchExecutionError::OutputBudget);
        }
        self.bytes += bytes;
        Ok(())
    }

    fn has_partial_result(&self) -> bool {
        self.items.iter().any(Option::is_some)
            || !self.durability.is_empty()
            || self.rejected_native_batch.is_some()
    }

    fn partial_value(&self) -> Value {
        let completed = self.items.iter().filter(|item| item.is_some()).count();
        let succeeded = self
            .items
            .iter()
            .filter_map(|item| item.as_ref())
            .filter(|item| item.error.is_none())
            .count();
        let mut partial = serde_json::json!({
            "items": self.items.iter().enumerate().filter_map(|(index, item)| item.as_ref().map(|item| {
                let procedure = item.procedure.as_ref().map(|procedure| serde_json::json!({
                    "status": "resolved",
                    "address": procedure.address,
                    "name": procedure.name,
                })).unwrap_or_else(|| serde_json::json!({ "status": "unknown" }));
                let mut projected = serde_json::json!({
                    "input_index": index,
                    "address": item.selector,
                    "procedure": procedure,
                    "status": if item.error.is_some() { "error" } else { "ok" },
                });
                if let Some(pseudocode) = &item.pseudocode {
                    projected["pseudocode"] = Value::String(pseudocode.clone());
                }
                if let Some(error) = &item.error {
                    projected["error"] = serde_json::json!({
                        "code": error.code,
                        "message": error.message,
                    });
                }
                projected
            })).collect::<Vec<_>>(),
            "total_requested": self.selectors.len(),
            "completed": completed,
            "succeeded": succeeded,
            "failed": completed.saturating_sub(succeeded),
            "durability": self.durability_value(),
        });
        if let Some(reply) = &self.rejected_native_batch {
            partial["rejected_native_batch"] = reply.clone();
        }
        partial
    }

    fn durability_value(&self) -> Value {
        serde_json::json!({
            "confirmed_addresses": self.durability.iter().filter_map(|(address, confirmed)| confirmed.then_some(address)).collect::<Vec<_>>(),
            "unconfirmed_addresses": self.durability.iter().filter_map(|(address, confirmed)| (!confirmed).then_some(address)).collect::<Vec<_>>(),
        })
    }

    fn finish(&self) -> Result<GhidraRustBatchResult, String> {
        let mut items = Vec::with_capacity(self.items.len());
        for item in &self.items {
            items.push(item.clone().ok_or_else(|| {
                "the native batch did not produce one result per input selector".to_owned()
            })?);
        }
        let succeeded = items.iter().filter(|item| item.error.is_none()).count();
        Ok(GhidraRustBatchResult {
            total: items.len(),
            failed: items.len() - succeeded,
            succeeded,
            items,
            confirmed_addresses: self
                .durability
                .iter()
                .filter_map(|(address, confirmed)| confirmed.then_some(address.clone()))
                .collect(),
            unconfirmed_addresses: self
                .durability
                .iter()
                .filter_map(|(address, confirmed)| (!confirmed).then_some(address.clone()))
                .collect(),
        })
    }
}
