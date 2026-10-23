//! Inventory-backed native batches with bounded retained output.
//!
//! Compatibility owners: `src/ghidra-rust/GhidraRustBatch.ts`,
//! `GhidraRustBatchPlan.ts`, `GhidraRustBatchItems.ts` and
//! `GhidraRustBatchReply.ts`.
use crate::identity::PROVIDER_ID;
use crate::protocol::{
    BatchItem, BatchReply, Durability, MAX_BATCH_BYTES, MAX_BATCH_SIZE, MAX_PSEUDOCODE_BYTES,
    MAX_REQUEST_BYTES, MAX_RESOLUTION_SELECTORS, ResolutionStatus, parse_batch_failure,
    parse_batch_reply,
};
use crate::selectors::{resolve_page, selector_error};
use crate::session::Session;
use crate::worker::{Control, worker_error};
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};

/// `MAX_RETAINED_BATCH_BYTES`.
const MAX_RETAINED_BATCH_BYTES: usize = 32 * 1024 * 1024;

/// Per-call batch controls (`GhidraRustBatchOptions`).
#[derive(Clone, Copy)]
pub(crate) struct BatchOptions {
    pub operation: &'static str,
    pub cache_only: bool,
}

/// One caller-selector result.
#[derive(Clone)]
pub(crate) enum Item {
    Ok {
        address: String,
        procedure_address: String,
        procedure_name: String,
        pseudocode: String,
    },
    Error {
        address: String,
        procedure: Option<(String, String)>,
        error: AnalysisError,
    },
}

/// `projectItem`: typed failures are projected only at public output.
fn project_item(item: &Item) -> Map<String, Value> {
    let mut object = Map::new();
    match item {
        Item::Ok {
            address,
            procedure_address,
            procedure_name,
            pseudocode,
        } => {
            object.insert("address".into(), json!(address));
            object.insert(
                "procedure".into(),
                json!({ "status": "resolved", "address": procedure_address, "name": procedure_name }),
            );
            object.insert("status".into(), json!("ok"));
            object.insert("pseudocode".into(), json!(pseudocode));
        }
        Item::Error {
            address,
            procedure,
            error,
        } => {
            let projected = error.project();
            object.insert("address".into(), json!(address));
            object.insert(
                "procedure".into(),
                match procedure {
                    Some((address, name)) => {
                        json!({ "status": "resolved", "address": address, "name": name })
                    }
                    None => json!({ "status": "unknown", "error": projected }),
                },
            );
            object.insert("status".into(), json!("error"));
            object.insert("error".into(), projected);
        }
    }
    object
}

/// A complete batch result.
pub(crate) struct BatchResult {
    pub items: Vec<Item>,
    durability: Value,
}

impl BatchResult {
    /// `projectGhidraRustBatchResult`.
    pub(crate) fn project(&self) -> Value {
        let succeeded = self
            .items
            .iter()
            .filter(|item| matches!(item, Item::Ok { .. }))
            .count();
        json!({
            "items": self.items.iter().map(|item| Value::Object(project_item(item))).collect::<Vec<_>>(),
            "total": self.items.len(),
            "succeeded": succeeded,
            "failed": self.items.len() - succeeded,
            "durability": self.durability,
        })
    }
}

/// `ghidraRustBatchItemError`.
pub(crate) fn item_error(item: &BatchItem, timeout_ms: u64, operation: &str) -> AnalysisError {
    let message = item
        .error_message
        .clone()
        .unwrap_or_else(|| "The worker returned no pseudocode.".to_owned());
    let mut diagnostics = Map::new();
    diagnostics.insert("worker_error_code".into(), json!(item.error_code));
    match item.error_code.as_deref() {
        Some("REQUEST_DEADLINE") => AnalysisError::timeout(operation, timeout_ms)
            .with_user_message(message)
            .with_remediation("Increase REA_GHIDRA_RUST_TIMEOUT_MS or select a smaller batch.")
            .with_diagnostics(diagnostics),
        Some(code @ ("OUTPUT_LIMIT" | "BATCH_OUTPUT_LIMIT")) => {
            AnalysisError::from(ErrorKind::ResourceConstraint {
                operation: operation.to_owned(),
                resource: "transport".to_owned(),
                reason: message,
                reported_limits: Some(if code == "BATCH_OUTPUT_LIMIT" {
                    json!({ "batch_bytes": MAX_BATCH_BYTES })
                } else {
                    json!({ "pseudocode_bytes": MAX_PSEUDOCODE_BYTES })
                }),
                remediation_action: None,
                retryable: Some(false),
            })
            .with_diagnostics(diagnostics)
        }
        _ => AnalysisError::output(operation, message).with_diagnostics(diagnostics),
    }
}

fn protocol_failure(operation: &str, message: &str) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("failure_kind".into(), json!("protocol"));
    AnalysisError::provider_adapter(PROVIDER_ID, operation)
        .with_user_message(message)
        .with_diagnostics(diagnostics)
}

/// `retainSecondaryFailure`.
fn retain_secondary(
    mut primary: AnalysisError,
    secondary: AnalysisError,
    diagnostics: Option<Map<String, Value>>,
) -> AnalysisError {
    if let Some(extra) = diagnostics {
        let mut merged = primary.diagnostics.take().unwrap_or_default();
        for (key, value) in extra {
            merged.insert(key, value);
        }
        primary.diagnostics = Some(merged);
    }
    primary.secondary_failures.push(secondary);
    primary
}

/// `GhidraRustBatchAccumulator`: bound serialized output while retaining one
/// slot for every input selector.
struct Accumulator<'a> {
    selectors: &'a [String],
    timeout_ms: u64,
    operation: &'static str,
    items: Vec<Option<Item>>,
    bytes: usize,
    completed: usize,
    succeeded: usize,
    durability: Vec<(String, bool)>,
    durability_index: HashMap<String, usize>,
    rejected_native_batch: Option<Value>,
}

impl<'a> Accumulator<'a> {
    fn new(selectors: &'a [String], timeout_ms: u64, operation: &'static str) -> Self {
        Self {
            selectors,
            timeout_ms,
            operation,
            items: vec![None; selectors.len()],
            bytes: 256,
            completed: 0,
            succeeded: 0,
            durability: Vec::new(),
            durability_index: HashMap::new(),
            rejected_native_batch: None,
        }
    }

    fn protocol(&self, message: &str) -> AnalysisError {
        protocol_failure(self.operation, message)
    }

    fn record_failure(&mut self, index: usize, error: AnalysisError) -> Result<(), AnalysisError> {
        let Some(selector) = self.selectors.get(index) else {
            return Err(self.protocol("Invalid batch result index."));
        };
        let item = Item::Error {
            address: selector.clone(),
            procedure: None,
            error,
        };
        self.record(index, item)
    }

    fn record_native(&mut self, indices: &[usize], item: &BatchItem) -> Result<(), AnalysisError> {
        for index in indices {
            let Some(selector) = self.selectors.get(*index) else {
                return Err(self.protocol("Invalid batch selector index."));
            };
            let native = native_item(selector, item, self.timeout_ms, self.operation);
            self.record(*index, native)?;
        }
        Ok(())
    }

    /// `recordDurability`: durability facts are kept even when normalized
    /// output admission must stop.
    fn record_durability(&mut self, receipt: &Durability) -> Result<(), AnalysisError> {
        let mut bytes = 0;
        let mut retain = |address: &String, confirmed: bool, this: &mut Self| match this
            .durability_index
            .get(address)
        {
            Some(position) => this.durability[*position].1 = confirmed,
            None => {
                bytes += serde_json::to_string(address).map_or(0, |text| text.len()) + 1;
                this.durability_index
                    .insert(address.clone(), this.durability.len());
                this.durability.push((address.clone(), confirmed));
            }
        };
        for address in &receipt.confirmed_addresses {
            retain(address, true, self);
        }
        for address in &receipt.unconfirmed_addresses {
            retain(address, false, self);
        }
        self.reserve(bytes)
    }

    fn durability_receipt(&self) -> Value {
        let confirmed = self
            .durability
            .iter()
            .filter(|(_, confirmed)| *confirmed)
            .map(|(address, _)| address.clone())
            .collect::<Vec<_>>();
        let unconfirmed = self
            .durability
            .iter()
            .filter(|(_, confirmed)| !*confirmed)
            .map(|(address, _)| address.clone())
            .collect::<Vec<_>>();
        json!({ "confirmed_addresses": confirmed, "unconfirmed_addresses": unconfirmed })
    }

    fn partial_result(&self) -> Option<Value> {
        if self.completed == 0 && self.durability.is_empty() && self.rejected_native_batch.is_none()
        {
            return None;
        }
        let items = self
            .items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| {
                item.as_ref().map(|item| {
                    let mut object = Map::new();
                    object.insert("input_index".into(), json!(index));
                    for (key, value) in project_item(item) {
                        object.insert(key, value);
                    }
                    Value::Object(object)
                })
            })
            .collect::<Vec<_>>();
        let mut partial = Map::new();
        let completed = items.len();
        partial.insert("items".into(), Value::Array(items));
        partial.insert("total_requested".into(), json!(self.selectors.len()));
        partial.insert("completed".into(), json!(completed));
        partial.insert("succeeded".into(), json!(self.succeeded));
        partial.insert("failed".into(), json!(completed - self.succeeded));
        partial.insert("durability".into(), self.durability_receipt());
        if let Some(rejected) = &self.rejected_native_batch {
            partial.insert("rejected_native_batch".into(), rejected.clone());
        }
        Some(Value::Object(partial))
    }

    fn finish(self) -> Result<BatchResult, AnalysisError> {
        if self.completed != self.selectors.len() {
            return Err(
                self.protocol("The native batch did not produce one result per input selector.")
            );
        }
        let durability = self.durability_receipt();
        let mut items = Vec::with_capacity(self.items.len());
        for item in self.items {
            let Some(item) = item else {
                return Err(protocol_failure(
                    self.operation,
                    "A completed batch result slot is empty.",
                ));
            };
            items.push(item);
        }
        Ok(BatchResult { items, durability })
    }

    fn record(&mut self, index: usize, item: Item) -> Result<(), AnalysisError> {
        if self.items.get(index).is_some_and(Option::is_some) {
            return Err(self.protocol("A batch result slot was completed more than once."));
        }
        let mut indexed = Map::new();
        indexed.insert("input_index".into(), json!(index));
        for (key, value) in project_item(&item) {
            indexed.insert(key, value);
        }
        let bytes = serde_json::to_string(&Value::Object(indexed))
            .map_or(usize::MAX / 2, |text| text.len())
            + 1;
        self.reserve(bytes)?;
        if matches!(item, Item::Ok { .. }) {
            self.succeeded += 1;
        }
        self.items[index] = Some(item);
        self.completed += 1;
        Ok(())
    }

    fn reserve(&mut self, bytes: usize) -> Result<(), AnalysisError> {
        if self.bytes + bytes > MAX_RETAINED_BATCH_BYTES {
            return Err(AnalysisError::from(ErrorKind::ResourceConstraint {
                operation: self.operation.to_owned(),
                resource: "transport".to_owned(),
                reason: "The normalized batch exceeds its retained output budget. Select fewer procedures.".to_owned(),
                reported_limits: Some(json!({ "maximum_serialized_bytes": MAX_RETAINED_BATCH_BYTES })),
                remediation_action: None,
                retryable: Some(false),
            }));
        }
        self.bytes += bytes;
        Ok(())
    }
}

/// `nativeItem`: preserve the caller's selector alongside the canonical
/// native procedure.
fn native_item(selector: &str, item: &BatchItem, timeout_ms: u64, operation: &str) -> Item {
    let procedure = match (&item.address, &item.name) {
        (Some(address), Some(name)) => Some((address.clone(), name.clone())),
        _ => None,
    };
    if let (Some(pseudocode), Some((address, name))) = (&item.pseudocode, &procedure) {
        return Item::Ok {
            address: selector.to_owned(),
            procedure_address: address.clone(),
            procedure_name: name.clone(),
            pseudocode: pseudocode.clone(),
        };
    }
    Item::Error {
        address: selector.to_owned(),
        procedure,
        error: item_error(item, timeout_ms, operation),
    }
}

/// One deduplicated resolved procedure and every input index selecting it.
struct Selected {
    address: String,
    name: String,
    indices: Vec<usize>,
}

/// `selectorPages`: JSON-RPC-safe pages built incrementally.
fn selector_pages(selectors: &[String]) -> Vec<Vec<usize>> {
    let envelope_reserve = 256;
    let empty_payload = r#"{"selectors":[]}"#.len();
    let maximum_payload = MAX_REQUEST_BYTES - envelope_reserve;
    let mut pages = Vec::new();
    let mut page: Vec<usize> = Vec::new();
    let mut payload = empty_payload;
    for (index, selector) in selectors.iter().enumerate() {
        let selector_bytes = serde_json::to_string(selector).map_or(0, |text| text.len());
        let comma = usize::from(!page.is_empty());
        if !page.is_empty()
            && (page.len() >= MAX_RESOLUTION_SELECTORS
                || payload + comma + selector_bytes > maximum_payload)
        {
            pages.push(std::mem::take(&mut page));
            payload = empty_payload;
        }
        page.push(index);
        payload += usize::from(page.len() > 1) + selector_bytes;
    }
    if !page.is_empty() {
        pages.push(page);
    }
    pages
}

/// `executeGhidraRustBatch`.
pub(crate) fn execute(
    session: &Session,
    selectors: &[String],
    options: BatchOptions,
    control: &Control,
) -> Result<BatchResult, AnalysisError> {
    if options.cache_only && session.info().is_none() {
        return Err(
            session.failure("Cache-only retrieval requires an already prepared worker session.")
        );
    }
    let mut accumulator = Accumulator::new(selectors, session.timeout_ms(), options.operation);
    let planned = plan(session, selectors, &mut accumulator, options, control);
    if let Err(failure) = planned {
        return Err(preserve_completed(
            session,
            &accumulator,
            selectors,
            failure,
        ));
    }
    let partial = accumulator.partial_result();
    accumulator.finish().map_err(|failure| match partial {
        Some(partial) => session.retain_batch_observation(failure, selectors, partial),
        None => failure,
    })
}

fn preserve_completed(
    session: &Session,
    accumulator: &Accumulator<'_>,
    selectors: &[String],
    failure: AnalysisError,
) -> AnalysisError {
    match accumulator.partial_result() {
        Some(partial) => session.retain_batch_observation(failure, selectors, partial),
        None => failure,
    }
}

/// `planGhidraRustBatch`: resolve bounded pages, retaining no duplicate
/// full-program inventory.
fn plan(
    session: &Session,
    selectors: &[String],
    accumulator: &mut Accumulator<'_>,
    options: BatchOptions,
    control: &Control,
) -> Result<(), AnalysisError> {
    // Resolution pages are small; native batches collect resolved procedures
    // across pages so each worker batch can occupy every decompiler thread.
    let mut selected: Vec<Selected> = Vec::new();
    let mut positions: HashMap<String, usize> = HashMap::new();
    for page in selector_pages(selectors) {
        if control.interruption().is_some() {
            return Err(AnalysisError::cancelled(options.operation));
        }
        let requested = page
            .iter()
            .map(|index| selectors[*index].clone())
            .collect::<Vec<_>>();
        let resolved = resolve_page(session, &requested, control, options.operation)?;
        for (page_index, result) in resolved.iter().enumerate() {
            let Some(index) = page.get(page_index).copied() else {
                return Err(accumulator.protocol("The worker returned an extra selector result."));
            };
            if result.status != ResolutionStatus::Found {
                accumulator.record_failure(
                    index,
                    selector_error(
                        options.operation,
                        result.status,
                        control.selector_from_provider,
                    ),
                )?;
                continue;
            }
            let (Some(address), Some(name)) = (&result.address, &result.name) else {
                return Err(accumulator.protocol("A resolved function lacks its identity."));
            };
            match positions.get(address) {
                Some(position) => selected[*position].indices.push(index),
                None => {
                    positions.insert(address.clone(), selected.len());
                    selected.push(Selected {
                        address: address.clone(),
                        name: name.clone(),
                        indices: vec![index],
                    });
                }
            }
        }
        // Run every full native batch now; a partial one waits for more pages.
        let chunks = native_chunks(&selected);
        let full = chunks.len().saturating_sub(1);
        let mut consumed = 0;
        for chunk in &chunks[..full] {
            execute_native(session, accumulator, chunk, options, control)?;
            consumed += chunk.len();
        }
        if consumed > 0 {
            selected.drain(..consumed);
            positions.clear();
            for (position, procedure) in selected.iter().enumerate() {
                positions.insert(procedure.address.clone(), position);
            }
        }
    }
    for chunk in native_chunks(&selected) {
        if control.interruption().is_some() {
            return Err(AnalysisError::cancelled(options.operation));
        }
        execute_native(session, accumulator, chunk, options, control)?;
    }
    Ok(())
}

/// The worker reserves a per-function recovery record in each reply; the
/// reserve must stay below its published budget (6 MiB batch frame minus the
/// unconfirmed-output and largest-item allowances, about 1.9 MiB).
const MAX_CHUNK_RECOVERY_BYTES: usize = 1536 * 1024;

/// Upper bound on one worker recovery record: fixed JSON and message text, two
/// canonical addresses, and the name with worst-case JSON escaping.
fn recovery_record_bytes(procedure: &Selected) -> usize {
    512 + 6 * procedure.name.len()
}

/// Native batches as large as the worker accepts, so one request keeps every
/// decompiler thread busy, while bounding the worker's recovery reserve.
fn native_chunks(selected: &[Selected]) -> Vec<&[Selected]> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut reserve = 0;
    for (index, procedure) in selected.iter().enumerate() {
        let bytes = recovery_record_bytes(procedure);
        if index > start
            && (index - start >= MAX_BATCH_SIZE || reserve + bytes > MAX_CHUNK_RECOVERY_BYTES)
        {
            chunks.push(&selected[start..index]);
            start = index;
            reserve = 0;
        }
        reserve += bytes;
    }
    if start < selected.len() {
        chunks.push(&selected[start..]);
    }
    chunks
}

/// `executeNativeBatch`.
fn execute_native(
    session: &Session,
    accumulator: &mut Accumulator<'_>,
    procedures: &[Selected],
    options: BatchOptions,
    control: &Control,
) -> Result<(), AnalysisError> {
    let batch = request(session, procedures, options, control, accumulator)?;
    let interruption = batch_interruption(&batch, options.operation);
    if interruption.is_none() {
        session.worker.acknowledge_validated_batch_checkpoint();
    }
    let cache_miss = batch
        .items
        .iter()
        .find(|item| item.error_code.as_deref() == Some("CACHE_MISS"));
    let failure = interruption.clone().or_else(|| {
        cache_miss.map(|item| item_error(item, session.timeout_ms(), options.operation))
    });
    let retained = record_completed(accumulator, procedures, &batch);
    if let Some(mut failure) = failure {
        if let Err(secondary) = retained {
            failure = retain_secondary(failure, secondary, None);
        }
        return Err(if interruption.is_none() {
            failure
        } else {
            session.worker.invalidate(failure)
        });
    }
    retained?;
    retrieve_output_limited(session, accumulator, procedures, &batch, options, control)
}

/// `retrieveOutputLimitedItems`: fetch cached items that exceeded the
/// combined batch budget in halved cache-only groups.
fn retrieve_output_limited(
    session: &Session,
    accumulator: &mut Accumulator<'_>,
    procedures: &[Selected],
    reply: &BatchReply,
    options: BatchOptions,
    control: &Control,
) -> Result<(), AnalysisError> {
    if procedures.len() <= 1 {
        return Ok(());
    }
    let pending = procedures
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            reply
                .items
                .get(*index)
                .is_some_and(|item| item.error_code.as_deref() == Some("BATCH_OUTPUT_LIMIT"))
        })
        .map(|(_, procedure)| Selected {
            address: procedure.address.clone(),
            name: procedure.name.clone(),
            indices: procedure.indices.clone(),
        })
        .collect::<Vec<_>>();
    let group = procedures.len().div_ceil(2);
    for chunk in pending.chunks(group) {
        execute_native(
            session,
            accumulator,
            chunk,
            BatchOptions {
                cache_only: true,
                ..options
            },
            control,
        )?;
    }
    Ok(())
}

/// `recordCompletedBatch`.
fn record_completed(
    accumulator: &mut Accumulator<'_>,
    procedures: &[Selected],
    batch: &BatchReply,
) -> Result<(), AnalysisError> {
    accumulator.record_durability(&batch.durability)?;
    for (index, item) in batch.items.iter().enumerate() {
        let Some(selection) = procedures.get(index) else {
            return Err(accumulator.protocol("A validated batch lost its selection."));
        };
        if item.error_code.as_deref() == Some("BATCH_OUTPUT_LIMIT")
            && (procedures.len() > 1 || batch.failure.is_some())
        {
            continue;
        }
        accumulator.record_native(&selection.indices, item)?;
    }
    Ok(())
}

/// `requestGhidraRustBatch`: validate the complete native receipt before
/// retaining caller output.
fn request(
    session: &Session,
    procedures: &[Selected],
    options: BatchOptions,
    control: &Control,
    accumulator: &mut Accumulator<'_>,
) -> Result<BatchReply, AnalysisError> {
    let addresses = procedures
        .iter()
        .map(|procedure| procedure.address.clone())
        .collect::<Vec<_>>();
    let mut parameters = Map::new();
    parameters.insert("addresses".into(), json!(addresses));
    if options.cache_only {
        parameters.insert("cache_only".into(), json!(true));
    }
    let response =
        session
            .worker
            .request("batch_decompile", Value::Object(parameters), Some(control))?;
    let batch = match parse_batch_reply(&response) {
        Ok(batch) => batch,
        Err(_) => {
            return Err(reject(
                session,
                accumulator,
                response,
                options,
                session.failure("Malformed Rust native batch response."),
            ));
        }
    };
    match validate(session, procedures, &batch) {
        None => Ok(batch),
        Some(failure) => Err(reject(session, accumulator, response, options, failure)),
    }
}

fn validate(
    session: &Session,
    procedures: &[Selected],
    batch: &BatchReply,
) -> Option<AnalysisError> {
    let output_bytes = batch
        .items
        .iter()
        .map(|item| serde_json::to_string(&item.raw).map_or(usize::MAX / 128, |text| text.len()))
        .sum::<usize>();
    let partial = batch.failure.is_some();
    let returned = batch.items.len();
    if batch.total != returned as u64
        || batch.completed != returned as u64
        || returned > procedures.len()
        || (!partial && returned != procedures.len())
        || Some(&batch.inventory_sha256) != session.inventory_sha256().as_ref()
        || output_bytes > MAX_BATCH_BYTES
        || !valid_durability(batch)
    {
        return Some(session.failure(
            "The native batch changed its inventory, output budget, completed prefix or durability contract.",
        ));
    }
    for (index, item) in batch.items.iter().enumerate() {
        if !procedures
            .get(index)
            .is_some_and(|selection| valid_item(item, selection))
        {
            return Some(
                session.failure("The native batch violated its procedure or per-item contract."),
            );
        }
    }
    None
}

/// `rejectNativeBatch`: retain rejected source evidence before invalidation.
fn reject(
    session: &Session,
    accumulator: &mut Accumulator<'_>,
    reply: Value,
    options: BatchOptions,
    validation_failure: AnalysisError,
) -> AnalysisError {
    let failure = match rejected_interruption(&reply, options.operation) {
        Some(interruption) => {
            let mut diagnostics = Map::new();
            diagnostics.insert(
                "batch_validation_failure".into(),
                validation_failure.project(),
            );
            retain_secondary(interruption, validation_failure, Some(diagnostics))
        }
        None => validation_failure,
    };
    accumulator.rejected_native_batch = Some(reply);
    session.worker.invalidate(failure)
}

fn rejected_interruption(reply: &Value, operation: &str) -> Option<AnalysisError> {
    let object = reply.as_object()?;
    let failure = parse_batch_failure(object.get("failure")?).ok()?;
    let mut diagnostics = Map::new();
    diagnostics.insert("worker_batch_error_code".into(), json!("BATCH_INTERRUPTED"));
    diagnostics.insert(
        "durability".into(),
        object.get("durability").cloned().unwrap_or(Value::Null),
    );
    Some(worker_error(
        operation,
        &failure.error_message,
        &failure.cause_code,
        diagnostics,
    ))
}

/// `ghidraRustBatchInterruption`: a failed commit and its exact durability
/// receipt are the primary error.
fn batch_interruption(batch: &BatchReply, operation: &str) -> Option<AnalysisError> {
    let failure = batch.failure.as_ref()?;
    let mut diagnostics = Map::new();
    diagnostics.insert("worker_batch_error_code".into(), json!("BATCH_INTERRUPTED"));
    diagnostics.insert(
        "confirmed_addresses".into(),
        json!(batch.durability.confirmed_addresses),
    );
    diagnostics.insert(
        "unconfirmed_addresses".into(),
        json!(batch.durability.unconfirmed_addresses),
    );
    Some(worker_error(
        operation,
        &failure.error_message,
        &failure.cause_code,
        diagnostics,
    ))
}

fn valid_durability(batch: &BatchReply) -> bool {
    let mut pseudocode = batch
        .items
        .iter()
        .filter(|item| {
            item.pseudocode.is_some() || item.error_code.as_deref() == Some("BATCH_OUTPUT_LIMIT")
        })
        .filter_map(|item| item.address.clone())
        .collect::<HashSet<_>>();
    let confirmed = batch
        .durability
        .confirmed_addresses
        .iter()
        .collect::<HashSet<_>>();
    let unconfirmed = batch
        .durability
        .unconfirmed_addresses
        .iter()
        .collect::<HashSet<_>>();
    if confirmed.len() != batch.durability.confirmed_addresses.len()
        || unconfirmed.len() != batch.durability.unconfirmed_addresses.len()
        || (batch.failure.is_none() && !unconfirmed.is_empty())
    {
        return false;
    }
    for address in &confirmed {
        if !pseudocode.remove(*address) {
            return false;
        }
    }
    for address in &unconfirmed {
        if confirmed.contains(address)
            || !pseudocode.remove(*address)
            || batch.items.iter().any(|item| {
                item.address.as_ref() == Some(*address)
                    && item.error_code.as_deref() == Some("BATCH_OUTPUT_LIMIT")
            })
        {
            return false;
        }
    }
    pseudocode.is_empty()
}

fn valid_item(item: &BatchItem, procedure: &Selected) -> bool {
    if item.selector != procedure.address
        || item.address.as_deref() != Some(procedure.address.as_str())
        || item.name.as_deref() != Some(procedure.name.as_str())
    {
        return false;
    }
    match &item.pseudocode {
        Some(pseudocode) => {
            !pseudocode.trim().is_empty()
                && item.error_code.is_none()
                && item.error_message.is_none()
        }
        None => item
            .error_message
            .as_ref()
            .is_some_and(|message| !message.trim().is_empty()),
    }
}
