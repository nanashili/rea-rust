//! Resolve caller or provider selectors against the worker's frozen index.
//!
//! Compatibility owner: `src/ghidra-rust/GhidraRustSelectors.ts`.
use crate::protocol::{
    MAX_REQUEST_BYTES, MAX_RESOLUTION_SELECTORS, Resolution, ResolutionStatus, parse_resolution,
};
use crate::session::Session;
use crate::worker::Control;
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use serde_json::{Map, Value, json};

const REQUEST_ENVELOPE_RESERVE: usize = 256;

/// Selector provenance determines whether a miss is input or provider
/// output (`ghidraRustSelectorError`).
pub(crate) fn selector_error(
    operation: &str,
    status: ResolutionStatus,
    selector_from_provider: bool,
) -> AnalysisError {
    let reason = if status == ResolutionStatus::Ambiguous {
        "The function name is ambiguous; select an inventory address."
    } else {
        "The selector is outside the frozen function inventory."
    };
    if selector_from_provider {
        AnalysisError::output(operation, reason)
    } else {
        AnalysisError::input_message(operation, reason, Vec::new())
    }
}

fn valid_request(selectors: &[String]) -> bool {
    !selectors.is_empty()
        && selectors.len() <= MAX_RESOLUTION_SELECTORS
        && serde_json::to_string(&json!({ "selectors": selectors }))
            .is_ok_and(|text| text.len() + REQUEST_ENVELOPE_RESERVE <= MAX_REQUEST_BYTES)
}

fn valid_item(item: &Resolution) -> bool {
    if item.status == ResolutionStatus::Found {
        item.address.is_some() && item.name.is_some()
    } else {
        item.address.is_none() && item.name.is_none()
    }
}

/// `resolvePage`.
pub(crate) fn resolve_page(
    session: &Session,
    selectors: &[String],
    control: &Control,
    operation: &str,
) -> Result<Vec<Resolution>, AnalysisError> {
    if !valid_request(selectors) {
        return Err(AnalysisError::from(ErrorKind::ResourceConstraint {
            operation: operation.to_owned(),
            resource: "capacity".to_owned(),
            reason: "The Rust worker resolution page exceeds its selector or frame budget."
                .to_owned(),
            reported_limits: Some(json!({
                "maximum_selectors": MAX_RESOLUTION_SELECTORS,
                "maximum_request_bytes": MAX_REQUEST_BYTES,
            })),
            remediation_action: None,
            retryable: Some(false),
        }));
    }
    let ready = session.prepare(control)?;
    let reply = session.worker.request(
        "resolve_functions",
        json!({ "selectors": selectors }),
        Some(control),
    )?;
    let page = parse_resolution(&reply).map_err(|_| {
        session.failure("The Rust worker returned an invalid selector-resolution page.")
    })?;
    if Some(&page.inventory_sha256) != ready.inventory_sha256.as_ref()
        || page.items.len() != selectors.len()
        || !page
            .items
            .iter()
            .zip(selectors)
            .all(|(item, selector)| item.selector == *selector && valid_item(item))
    {
        return Err(
            session.failure("Selector resolution differs from the frozen inventory or request.")
        );
    }
    Ok(page.items)
}

/// `resolve`: one canonical procedure address.
pub(crate) fn resolve(
    session: &Session,
    selector: &str,
    control: &Control,
) -> Result<Value, AnalysisError> {
    let page = resolve_page(
        session,
        &[selector.to_owned()],
        control,
        "procedure_address",
    )?;
    let Some(item) = page.first() else {
        return Err(session.failure("The worker omitted a selector result."));
    };
    match (&item.status, &item.address) {
        (ResolutionStatus::Found, Some(address)) => Ok(json!(address)),
        _ => Err(selector_error(
            "procedure_address",
            item.status,
            control.selector_from_provider,
        )),
    }
}

/// `addressName`: the inventory name at an explicit address, or null.
pub(crate) fn address_name(
    session: &Session,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<Value, AnalysisError> {
    let Some(address) = input.get("address").and_then(Value::as_str) else {
        return Err(AnalysisError::input_message(
            "address_name",
            "The Rust worker requires an explicit inventory address.",
            Vec::new(),
        ));
    };
    let page = resolve_page(session, &[address.to_owned()], control, "address_name")?;
    let Some(item) = page.first() else {
        return Err(session.failure("The worker omitted an address-name result."));
    };
    match item.status {
        ResolutionStatus::Ambiguous => {
            Err(session.failure("An address resolved as an ambiguous symbol."))
        }
        ResolutionStatus::Found => Ok(json!(item.name)),
        ResolutionStatus::NotFound => Ok(Value::Null),
    }
}
