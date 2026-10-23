//! Ordered batch decompilation.
//!
//! Compatibility owners: `#batchDecompile` and its helpers in
//! `EnhancedTools.ts`, `batchDecompileValueSchema`
//! (`contracts/batchDecompileOutput.ts`) and `resolveProcedureAddress`
//! (`ProcedureAddressResolution.ts`).
use crate::analysis::{Analysis, is_cancellation, params};
use crate::domain::error_projection::analysis_error_projection;
use crate::zod::{
    Schema, array, discriminated, field, int_min, literal_str, nullable, object, optional, refine,
    strict, string, string_min,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::sync::OnceLock;

/// `resolveProcedureAddress`: an observed canonical procedure identity.
pub fn resolve_procedure_address(
    analysis: &Analysis<'_>,
    procedure: &str,
) -> Result<String, AnalysisError> {
    let value = analysis.call(
        "procedure_address",
        &params([("procedure", json!(procedure))]),
        false,
    )?;
    match value {
        Value::String(address) if !address.is_empty() => Ok(address),
        _ => Err(AnalysisError::output(
            "procedure_address",
            "provider returned no canonical procedure address",
        )),
    }
}

fn counters_agree(value: &Value) -> Result<(), String> {
    let items = value["items"].as_array().cloned().unwrap_or_default();
    let succeeded = items.iter().filter(|item| item["status"] == "ok").count();
    let count = |key: &str| crate::zod::integer(&value[key]);
    if count("total") != Some(items.len() as i64)
        || count("succeeded") != Some(succeeded as i64)
        || count("failed") != Some((items.len() - succeeded) as i64)
    {
        return Err("Batch counters must describe the returned item statuses.".into());
    }
    validate_durability(value, &items)
}

fn validate_durability(value: &Value, items: &[Value]) -> Result<(), String> {
    let Some(durability) = value.get("durability") else {
        return Ok(());
    };
    let receipt = durability["confirmed_addresses"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(
            durability["unconfirmed_addresses"]
                .as_array()
                .into_iter()
                .flatten(),
        )
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let received = receipt.iter().copied().collect::<HashSet<_>>();
    if received.len() != receipt.len() {
        return Err("Durability addresses must be unique and nonoverlapping.".into());
    }
    let resolved = items
        .iter()
        .filter(|item| item["procedure"]["status"] == "resolved")
        .filter_map(|item| item["procedure"]["address"].as_str())
        .collect::<HashSet<_>>();
    if receipt.iter().any(|address| !resolved.contains(address)) {
        return Err("Durability addresses must belong to returned resolved procedures.".into());
    }
    for item in items {
        if item["status"] == "ok"
            && (item["procedure"]["status"] != "resolved"
                || !item["procedure"]["address"]
                    .as_str()
                    .is_some_and(|address| received.contains(address)))
        {
            return Err("Durability must classify every returned pseudocode procedure.".into());
        }
    }
    Ok(())
}

fn build_value_schema() -> Schema {
    let error = || analysis_error_projection().clone();
    let procedure = || {
        discriminated(
            "status",
            vec![
                object(vec![
                    field("status", literal_str("resolved")),
                    field("address", string_min(1)),
                    field("name", nullable(string())),
                    optional("name_error", error()),
                ]),
                object(vec![
                    field("status", literal_str("unknown")),
                    field("error", error()),
                ]),
            ],
        )
    };
    let item = discriminated(
        "status",
        vec![
            object(vec![
                field("address", string()),
                field("procedure", procedure()),
                field("status", literal_str("ok")),
                field("pseudocode", string_min(1)),
            ]),
            object(vec![
                field("address", string()),
                field("procedure", procedure()),
                field("status", literal_str("error")),
                field("error", error()),
            ]),
        ],
    );
    refine(
        object(vec![
            field("items", array(item)),
            field("total", int_min(0)),
            field("succeeded", int_min(0)),
            field("failed", int_min(0)),
            optional(
                "durability",
                strict(vec![
                    field("confirmed_addresses", array(string_min(1))),
                    field("unconfirmed_addresses", array(string_min(1))),
                ]),
            ),
        ]),
        counters_agree,
    )
}

/// `batchDecompileValueSchema` (built once).
fn batch_value_schema() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(build_value_schema)
}

/// `validateBatchSelectorOrder`.
fn validate_selector_order(value: &Value, requested: &[String]) -> Option<&'static str> {
    let items = value["items"].as_array()?;
    if items.len() != requested.len() {
        return Some("provider returned a different batch cardinality");
    }
    for (item, address) in items.iter().zip(requested) {
        if item["address"].as_str() != Some(address.as_str()) {
            return Some("provider changed batch selector order or identity");
        }
    }
    None
}

fn with_provider(analysis: &Analysis<'_>, addresses: &[String]) -> Result<Value, AnalysisError> {
    let value = analysis.call(
        "batch_decompile",
        &params([("addresses", json!(addresses))]),
        false,
    )?;
    let parsed = batch_value_schema().parse(&value).map_err(|_| {
        AnalysisError::output(
            "batch_decompile",
            "provider returned an invalid batch result",
        )
    })?;
    match validate_selector_order(&parsed, addresses) {
        None => Ok(parsed),
        Some(reason) => Err(AnalysisError::output("batch_decompile", reason)),
    }
}

/// `#batchProcedureIdentity`: the canonical entry and its label, or the
/// label failure; only cancellation fails the item.
fn procedure_identity(analysis: &Analysis<'_>, address: &str) -> Result<Value, AnalysisError> {
    let observed = analysis.call(
        "address_name",
        &params([("address", json!(address))]),
        false,
    );
    if let Err(error) = &observed
        && is_cancellation(error)
    {
        return Err(error.clone());
    }
    let mut identity = Map::new();
    identity.insert("status".into(), json!("resolved"));
    identity.insert("address".into(), json!(address));
    match observed {
        Ok(name @ (Value::String(_) | Value::Null)) => {
            identity.insert("name".into(), name);
        }
        Ok(_) => {
            identity.insert("name".into(), Value::Null);
            identity.insert(
                "name_error".into(),
                AnalysisError::output("address_name", "provider returned an invalid entry label")
                    .project(),
            );
        }
        Err(error) => {
            identity.insert("name".into(), Value::Null);
            identity.insert("name_error".into(), error.project());
        }
    }
    Ok(Value::Object(identity))
}

struct Ready {
    address: String,
    procedure: Value,
    provider_procedure: String,
    resolved: bool,
}

/// The first cancellation among phase results, in selector order.
fn first_cancellation<T>(results: &[Result<T, AnalysisError>]) -> Option<AnalysisError> {
    results.iter().find_map(|result| {
        result
            .as_ref()
            .err()
            .filter(|error| is_cancellation(error))
            .cloned()
    })
}

/// `#batchDecompile`.
pub fn batch_decompile(
    analysis: &Analysis<'_>,
    addresses: &[String],
) -> Result<Value, AnalysisError> {
    if analysis.supports("batch_decompile") {
        return with_provider(analysis, addresses);
    }
    // Each phase completes for every selector before the next begins.
    let resolutions = addresses
        .iter()
        .map(|address| resolve_procedure_address(analysis, address))
        .collect::<Vec<_>>();
    if let Some(cancelled) = first_cancellation(&resolutions) {
        return Err(cancelled);
    }
    let identities = addresses
        .iter()
        .zip(resolutions)
        .map(|(address, resolution)| match resolution {
            Err(error) => Ok(Ready {
                address: address.clone(),
                procedure: json!({ "status": "unknown", "error": error.project() }),
                provider_procedure: address.clone(),
                resolved: false,
            }),
            Ok(resolved) => procedure_identity(analysis, &resolved).map(|procedure| Ready {
                address: address.clone(),
                procedure,
                provider_procedure: resolved,
                resolved: true,
            }),
        })
        .collect::<Vec<_>>();
    let mut ready = Vec::with_capacity(identities.len());
    for identity in identities {
        ready.push(identity?);
    }
    let decompilations = ready
        .into_iter()
        .map(|item| {
            let result = analysis.call(
                "procedure_pseudo_code",
                &params([("procedure", json!(item.provider_procedure))]),
                item.resolved,
            );
            let mut entry = Map::new();
            entry.insert("address".into(), json!(item.address));
            entry.insert("procedure".into(), item.procedure);
            match result {
                Err(error) if is_cancellation(&error) => return Err(error),
                Err(error) => {
                    entry.insert("status".into(), json!("error"));
                    entry.insert("error".into(), error.project());
                }
                Ok(Value::String(pseudocode)) if !pseudocode.is_empty() => {
                    entry.insert("status".into(), json!("ok"));
                    entry.insert("pseudocode".into(), Value::String(pseudocode));
                }
                Ok(_) => {
                    entry.insert("status".into(), json!("error"));
                    entry.insert(
                        "error".into(),
                        AnalysisError::output(
                            "procedure_pseudo_code",
                            "provider returned empty pseudocode",
                        )
                        .project(),
                    );
                }
            }
            Ok(Value::Object(entry))
        })
        .collect::<Vec<_>>();
    let mut items = Vec::with_capacity(decompilations.len());
    for decompilation in decompilations {
        items.push(decompilation?);
    }
    let succeeded = items.iter().filter(|item| item["status"] == "ok").count();
    Ok(json!({
        "items": items,
        "total": items.len(),
        "succeeded": succeeded,
        "failed": items.len() - succeeded,
    }))
}
