//! Runtime boundary for ordered batch decompilation.

use rea_application::native::batch_decompile;
use rea_core::failure::{Detail, Failure};
use rea_host::ghidra_rust::protocol::{MAX_BATCH_SIZE, MAX_RESOLUTION_SELECTORS, WorkerFrame};
use rea_host::ghidra_rust::provider::{GhidraRustProvider, ProviderConfig, ProviderError};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const OPERATION: &str = batch_decompile::OPERATION;

/// Caller-selected identity for the target opened by the Rust Ghidra worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhidraRustTarget {
    pub path: String,
    pub sha256: String,
}

/// Runtime-owned cancellation boundary for live provider execution.
pub struct GhidraRustBatchContext<'a> {
    pub target: &'a GhidraRustTarget,
    pub cancelled: &'a dyn Fn() -> bool,
}

/// Project retained output or run an explicitly selected Rust Ghidra provider.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    batch_decompile::validate_input(&input)?;

    if input.get("result").is_some() || input.get("evidence").is_some() {
        return batch_decompile::project(&input);
    }

    Err(configuration_failure(
        "live Rust Ghidra execution requires an explicit target and cancellation adapter",
    ))
}

/// Execute a caller-authorized live batch with an explicit target identity.
pub fn dispatch_with_context(
    input: Value,
    context: GhidraRustBatchContext<'_>,
) -> Result<Value, Failure> {
    batch_decompile::validate_input(&input)?;

    if input.get("result").is_some() || input.get("evidence").is_some() {
        return batch_decompile::project(&input);
    }

    execute_live(&input, context)
}

fn execute_live(input: &Value, context: GhidraRustBatchContext<'_>) -> Result<Value, Failure> {
    validate_target(context.target)?;
    check_cancelled(context.cancelled)?;
    let config = ProviderConfig::from_environment().map_err(provider_failure)?;
    let mut provider = GhidraRustProvider::start(config).map_err(provider_failure)?;

    let execution = execute_session(&mut provider, input, context);
    let cleanup = provider.close();

    match (execution, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Ok(_), Err(error)) => Err(cleanup_failure(error)),
        (Err(failure), Ok(())) => Err(failure),
        (Err(mut failure), Err(error)) => {
            failure.detail("cleanup_failure", Detail::Text(error.to_string()));
            Err(failure)
        }
    }
}

fn validate_target(target: &GhidraRustTarget) -> Result<(), Failure> {
    if target.path.is_empty() || !Path::new(&target.path).is_absolute() {
        return Err(configuration_failure(
            "the selected Rust Ghidra target path must be absolute",
        ));
    }
    if target.sha256.len() != 64
        || !target
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(configuration_failure(
            "the selected Rust Ghidra target must use a lowercase SHA-256 digest",
        ));
    }
    Ok(())
}

fn execute_session(
    provider: &mut GhidraRustProvider,
    input: &Value,
    context: GhidraRustBatchContext<'_>,
) -> Result<Value, Failure> {
    check_cancelled(context.cancelled)?;
    let info = provider
        .open_with_cancel(
            &context.target.path,
            &context.target.sha256,
            context.cancelled,
        )
        .map_err(provider_failure)?;
    let addresses = input
        .get("addresses")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let plan = resolve_selectors(
        provider,
        &addresses,
        info.inventory_sha256.as_deref(),
        context.cancelled,
    )?;
    let mut result = BatchResult::new(&addresses);
    for (index, failure) in plan.unresolved {
        result.record(index, failure)?;
    }
    for chunk in plan.selected.chunks(MAX_BATCH_SIZE) {
        check_cancelled(context.cancelled)?;
        let selectors = chunk
            .iter()
            .map(|procedure| procedure.address.clone())
            .collect::<Vec<_>>();
        let frame = provider
            .batch_decompile_with_cancel(&selectors, context.cancelled)
            .map_err(provider_failure)?;
        let normalized = worker_batch_result(frame, chunk, info.inventory_sha256.as_deref())?;
        result.record_selected(chunk, normalized.items)?;
        result.merge_durability(normalized.durability)?;
        if let Some(mut failure) = normalized.failure {
            failure.retain(&result.partial_value()).map_err(|error| {
                protocol_failure(&format!("failed to retain partial batch result: {error}"))
            })?;
            return Err(failure);
        }
        provider
            .checkpoint_with_cancel(context.cancelled)
            .map_err(provider_failure)?;
    }

    batch_decompile::retain_result(input, result.finish()?)
}

#[derive(Clone, Debug)]
struct SelectedProcedure {
    address: String,
    name: String,
    indices: Vec<usize>,
}

struct ResolvedPlan {
    selected: Vec<SelectedProcedure>,
    unresolved: Vec<(usize, Value)>,
}

struct NormalizedWorkerBatch {
    items: Vec<Value>,
    durability: Value,
    failure: Option<Failure>,
}

fn resolve_selectors(
    provider: &mut GhidraRustProvider,
    selectors: &[String],
    expected_inventory: Option<&str>,
    cancelled: &dyn Fn() -> bool,
) -> Result<ResolvedPlan, Failure> {
    let mut selected: Vec<SelectedProcedure> = Vec::new();
    let mut unresolved = Vec::new();
    for (page_start, page) in selectors.chunks(MAX_RESOLUTION_SELECTORS).enumerate() {
        check_cancelled(cancelled)?;
        let resolution = provider
            .resolve_functions_with_cancel(page, cancelled)
            .map_err(provider_failure)?;
        if resolution.inventory_sha256 != expected_inventory.unwrap_or_default() {
            return Err(integrity_failure(
                "worker resolution inventory identity changed",
            ));
        }
        if resolution.items.len() != page.len() {
            return Err(protocol_failure(
                "worker resolution did not return one item per selector",
            ));
        }
        for (offset, item) in resolution.items.into_iter().enumerate() {
            let index = page_start * MAX_RESOLUTION_SELECTORS + offset;
            if item.selector != page[offset] {
                return Err(protocol_failure("worker resolution changed selector order"));
            }
            if item.status != "found" {
                unresolved.push((
                    index,
                    json!({
                        "address": page[offset],
                        "procedure": {"status": "unknown"},
                        "status": "error",
                        "error": {
                            "code": "invalid_request",
                            "category": "invalid_input",
                            "message": selector_failure_message(&item.status),
                            "retryable": false,
                            "remediation": {"action": "Select an inventory address and retry."},
                            "details": {"operation": OPERATION}
                        }
                    }),
                ));
                continue;
            }
            let address = item
                .address
                .ok_or_else(|| protocol_failure("resolved function lacks its address"))?;
            let name = item
                .name
                .ok_or_else(|| protocol_failure("resolved function lacks its name"))?;
            if let Some(existing) = selected
                .iter_mut()
                .find(|procedure| procedure.address == address)
            {
                existing.indices.push(index);
            } else {
                selected.push(SelectedProcedure {
                    address,
                    name,
                    indices: vec![index],
                });
            }
        }
    }
    Ok(ResolvedPlan {
        selected,
        unresolved,
    })
}

fn selector_failure_message(status: &str) -> String {
    if status == "ambiguous" {
        "The function name is ambiguous; select an inventory address.".into()
    } else {
        "The selector is outside the frozen function inventory.".into()
    }
}

fn check_cancelled(cancelled: &dyn Fn() -> bool) -> Result<(), Failure> {
    if cancelled() {
        return Err(provider_failure(ProviderError::Cancelled));
    }
    Ok(())
}

fn worker_batch_result(
    frame: WorkerFrame,
    procedures: &[SelectedProcedure],
    expected_inventory: Option<&str>,
) -> Result<NormalizedWorkerBatch, Failure> {
    let selectors = procedures
        .iter()
        .map(|procedure| procedure.address.clone())
        .collect::<Vec<_>>();
    let value = match frame {
        WorkerFrame::Reply { result, .. } => result,
        WorkerFrame::Error {
            code,
            message,
            error_code,
            ..
        } => return Err(worker_failure(code, message, error_code)),
        WorkerFrame::Progress { .. } => {
            return Err(protocol_failure(
                "worker returned progress without a batch reply",
            ));
        }
    };
    let object = value
        .as_object()
        .ok_or_else(|| protocol_failure("worker batch result must be an object"))?;
    if object.get("inventory_sha256").and_then(Value::as_str) != expected_inventory {
        return Err(integrity_failure("worker batch inventory identity changed"));
    }

    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| protocol_failure("worker batch result is missing items"))?;
    let partial = object.get("failure").is_some();
    if items.len() > selectors.len() || (!partial && items.len() != selectors.len()) {
        return Err(protocol_failure(
            "worker batch did not return one item per selector",
        ));
    }
    if object.get("total").and_then(Value::as_u64) != Some(items.len() as u64)
        || object.get("completed").and_then(Value::as_u64) != Some(items.len() as u64)
    {
        return Err(protocol_failure(
            "worker batch counters do not describe returned items",
        ));
    }
    let durability = object
        .get("durability")
        .and_then(Value::as_object)
        .ok_or_else(|| protocol_failure("worker batch result is missing durability"))?;
    if durability
        .get("confirmed_addresses")
        .and_then(Value::as_array)
        .is_none()
        || durability
            .get("unconfirmed_addresses")
            .and_then(Value::as_array)
            .is_none()
    {
        return Err(protocol_failure("worker batch durability is incomplete"));
    }

    let mut normalized = Vec::with_capacity(items.len());
    for (procedure, item) in procedures.iter().zip(items) {
        normalized.push(normalize_item(procedure, item)?);
    }

    Ok(NormalizedWorkerBatch {
        items: normalized,
        durability: Value::Object(durability.clone()),
        failure: object.get("failure").map(|raw_failure| {
            let message = raw_failure
                .get("error_message")
                .and_then(Value::as_str)
                .unwrap_or("Rust Ghidra worker batch failed");
            let mut failure = protocol_failure(message);
            if let Some(code) = raw_failure.get("error_code").and_then(Value::as_str) {
                failure.detail("worker_error_code", Detail::Text(code.to_owned()));
            }
            failure
        }),
    })
}

fn normalize_item(procedure: &SelectedProcedure, value: &Value) -> Result<Value, Failure> {
    let selector = procedure.address.as_str();
    let object = value
        .as_object()
        .ok_or_else(|| protocol_failure("worker batch item must be an object"))?;
    if object.get("selector").and_then(Value::as_str) != Some(selector) {
        return Err(protocol_failure("worker batch item changed selector order"));
    }
    if object.get("address").and_then(Value::as_str) != Some(selector)
        || object.get("name").and_then(Value::as_str) != Some(procedure.name.as_str())
    {
        return Err(protocol_failure(
            "worker batch item changed procedure identity",
        ));
    }

    let procedure = match (
        object.get("address").and_then(Value::as_str),
        object.get("name").and_then(Value::as_str),
    ) {
        (Some(address), Some(name)) => json!({
            "status": "resolved",
            "address": address,
            "name": name,
        }),
        _ => json!({
            "status": "unknown",
            "error": item_error(object),
        }),
    };

    match object.get("pseudocode").and_then(Value::as_str) {
        Some(pseudocode) if !pseudocode.is_empty() => Ok(json!({
            "address": selector,
            "procedure": procedure,
            "status": "ok",
            "pseudocode": pseudocode,
        })),
        _ => Ok(json!({
            "address": selector,
            "procedure": procedure,
            "status": "error",
            "error": item_error(object),
        })),
    }
}

fn item_error(object: &Map<String, Value>) -> Value {
    let worker_code = object
        .get("error_code")
        .and_then(Value::as_str)
        .unwrap_or("WORKER_ITEM_FAILED");
    let message = object
        .get("error_message")
        .and_then(Value::as_str)
        .filter(|message| !message.is_empty())
        .unwrap_or("Rust Ghidra worker could not decompile the procedure");
    json!({
        "code": "execution_failure",
        "category": "execution_failure",
        "message": message,
        "retryable": false,
        "remediation": { "action": "Inspect worker diagnostics and retry the procedure." },
        "details": { "operation": OPERATION, "worker_error_code": worker_code },
    })
}

struct BatchResult {
    selectors: Vec<String>,
    items: Vec<Option<Value>>,
    durability_confirmed: BTreeSet<String>,
    durability_unconfirmed: BTreeSet<String>,
}

impl BatchResult {
    fn new(selectors: &[String]) -> Self {
        Self {
            selectors: selectors.to_vec(),
            items: vec![None; selectors.len()],
            durability_confirmed: BTreeSet::new(),
            durability_unconfirmed: BTreeSet::new(),
        }
    }

    fn record(&mut self, index: usize, item: Value) -> Result<(), Failure> {
        let slot = self
            .items
            .get_mut(index)
            .ok_or_else(|| protocol_failure("batch result index is outside the request"))?;
        if slot.is_some() {
            return Err(protocol_failure(
                "batch result slot was completed more than once",
            ));
        }
        *slot = Some(item);
        Ok(())
    }

    fn record_selected(
        &mut self,
        selected: &[SelectedProcedure],
        items: Vec<Value>,
    ) -> Result<(), Failure> {
        if selected.len() != items.len() {
            return Err(protocol_failure(
                "normalized worker batch item count changed",
            ));
        }
        for (procedure, item) in selected.iter().zip(items) {
            for index in &procedure.indices {
                let mut projected = item.clone();
                if let Some(object) = projected.as_object_mut() {
                    object.insert(
                        "address".into(),
                        Value::String(
                            self.selector_at(*index)
                                .ok_or_else(|| protocol_failure("batch selector index is invalid"))?
                                .to_owned(),
                        ),
                    );
                }
                self.record(*index, projected)?;
            }
        }
        Ok(())
    }

    fn selector_at(&self, index: usize) -> Option<&str> {
        self.selectors.get(index).map(String::as_str)
    }

    fn merge_durability(&mut self, durability: Value) -> Result<(), Failure> {
        let durability = durability
            .as_object()
            .ok_or_else(|| protocol_failure("worker batch is missing durability"))?;
        collect_addresses(
            durability.get("confirmed_addresses"),
            &mut self.durability_confirmed,
        )?;
        collect_addresses(
            durability.get("unconfirmed_addresses"),
            &mut self.durability_unconfirmed,
        )?;
        Ok(())
    }

    fn finish(self) -> Result<Value, Failure> {
        let items = self.complete_items()?;
        let succeeded = items
            .iter()
            .filter(|item| item.get("status").and_then(Value::as_str) == Some("ok"))
            .count();
        let total = items.len();
        Ok(json!({
            "items": items,
            "total": total,
            "succeeded": succeeded,
            "failed": total - succeeded,
            "durability": {
                "confirmed_addresses": self.durability_confirmed.into_iter().collect::<Vec<_>>(),
                "unconfirmed_addresses": self.durability_unconfirmed.into_iter().collect::<Vec<_>>(),
            },
        }))
    }

    fn complete_items(&self) -> Result<Vec<Value>, Failure> {
        self.items
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, item)| {
                item.ok_or_else(|| {
                    protocol_failure(&format!("batch result is missing selector index {index}"))
                })
            })
            .collect()
    }

    fn partial_value(&self) -> Value {
        json!({
            "items": self.items.iter().filter_map(Option::as_ref).cloned().collect::<Vec<_>>(),
            "total": self.selectors.len(),
            "completed": self.items.iter().filter(|item| item.is_some()).count(),
            "succeeded": self.items.iter().filter_map(Option::as_ref).filter(|item| item.get("status").and_then(Value::as_str) == Some("ok")).count(),
            "failed": self.items.iter().filter_map(Option::as_ref).filter(|item| item.get("status").and_then(Value::as_str) == Some("error")).count(),
            "durability": {
                "confirmed_addresses": self.durability_confirmed.iter().collect::<Vec<_>>(),
                "unconfirmed_addresses": self.durability_unconfirmed.iter().collect::<Vec<_>>(),
            },
        })
    }
}

fn collect_addresses(value: Option<&Value>, output: &mut BTreeSet<String>) -> Result<(), Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| protocol_failure("worker durability addresses must be an array"))?;
    for address in values {
        let address = address
            .as_str()
            .filter(|address| !address.is_empty())
            .ok_or_else(|| protocol_failure("worker durability address must be non-empty"))?;
        output.insert(address.to_owned());
    }
    Ok(())
}

fn provider_failure(error: ProviderError) -> Failure {
    let (code, category, retryable) = match &error {
        ProviderError::Cancelled => ("cancelled", "cancelled", false),
        ProviderError::Timeout => ("provider_timeout", "timeout", true),
        ProviderError::Unavailable(_) => ("capability_unavailable", "unavailable", false),
        ProviderError::InvalidConfiguration(_) => ("configuration_invalid", "invalid_input", false),
        ProviderError::Launch(_) => ("provider_unavailable", "unavailable", true),
        ProviderError::Protocol(_) | ProviderError::Transport(_) => {
            ("execution_failure", "execution_failure", false)
        }
    };
    Failure::new(
        code,
        category,
        error.to_string(),
        retryable,
        "Inspect provider configuration and worker diagnostics before retrying.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn worker_failure(code: i64, message: String, error_code: Option<String>) -> Failure {
    let mut failure = provider_failure(ProviderError::Transport(format!(
        "worker request failed with {code}: {message}"
    )));
    if let Some(error_code) = error_code {
        failure.detail("worker_error_code", Detail::Text(error_code));
    }
    failure
}

fn configuration_failure(message: &str) -> Failure {
    Failure::new(
        "configuration_invalid",
        "invalid_input",
        message.into(),
        false,
        "Provide the explicit Rust Ghidra target configuration.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn protocol_failure(message: &str) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        message.into(),
        false,
        "Inspect the Rust Ghidra worker protocol diagnostics.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn integrity_failure(message: &str) -> Failure {
    Failure::new(
        "artifact_integrity_mismatch",
        "integrity_mismatch",
        message.into(),
        false,
        "Reopen the target and retry with a matching worker inventory.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn cleanup_failure(error: ProviderError) -> Failure {
    let mut failure = provider_failure(error);
    failure.detail("cleanup_incomplete", Detail::Flag(true));
    failure
}
