//! Provider-neutral projection for the session navigation context.
//!
//! A host adapter supplies the already retained observations in provider order.
//! This module does not query a GUI, move a cursor, or infer a document or
//! procedure from an unrelated observation.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const OPERATION: &str = "get_navigation_context";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Input {
    /// Caller-selected document.  The adapter may leave this omitted when it
    /// retained the current document observation.
    pub requested_document: Option<String>,
    pub document: Retained<String>,
    pub address: Retained<String>,
    pub procedure: Retained<ProcedureObservation>,
    /// Evidence IDs in the order of the observations that produced the result.
    pub evidence_links: Vec<String>,
    pub source_order: Vec<SourceObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Retained<T> {
    Omitted,
    Unavailable {
        reason: String,
        remediation: String,
    },
    Available {
        value: T,
        evidence_links: Vec<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProcedureObservation {
    Containing { name: String },
    OutsideProcedure,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceObservation {
    pub operation: String,
    pub evidence_links: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NavigationContext {
    pub document: String,
    /// The address is a string when the provider retained a cursor and an
    /// unavailable facet when the provider has no cursor surface.
    pub address: serde_json::Value,
    /// The procedure is a name, null for an address outside a procedure, or
    /// an unavailable facet when the address itself is unavailable.
    pub procedure: serde_json::Value,
    pub procedure_state: Retained<ProcedureObservation>,
    pub evidence_links: Vec<String>,
    pub source_order: Vec<SourceObservation>,
    pub unknowns: Vec<String>,
}

/// Project retained sequential observations into the provider-neutral result.
pub fn project(input: Input) -> Result<NavigationContext, Failure> {
    let document = available_text(&input.document, "document")?;
    let address = retained_address(&input.address)?;
    validate_requested_document(input.requested_document.as_deref())?;
    validate_source_order(&input.source_order)?;
    validate_evidence_links(&input.evidence_links)?;

    let procedure = procedure_value(&input.procedure);
    let mut unknowns = Vec::new();
    if matches!(input.procedure, Retained::Omitted) {
        unknowns.push("Containing procedure observation was omitted.".into());
    }
    if matches!(input.procedure, Retained::Unavailable { .. }) {
        unknowns.push("Containing procedure observation is unavailable.".into());
    }
    if input.source_order.is_empty() {
        unknowns.push("Observation source order was omitted.".into());
    }

    Ok(NavigationContext {
        document,
        address,
        procedure,
        procedure_state: input.procedure,
        evidence_links: input.evidence_links,
        source_order: input.source_order,
        unknowns,
    })
}

/// Parse adapter-shaped JSON while keeping all retained state explicit.
pub fn project_value(input: &serde_json::Value) -> Result<serde_json::Value, Failure> {
    let retained: Input = serde_json::from_value(input.clone())
        .map_err(|_| invalid("navigation context input has an invalid retained-state shape"))?;
    serde_json::to_value(project(retained)?).map_err(|_| invalid("result is not serializable"))
}

fn procedure_value(procedure: &Retained<ProcedureObservation>) -> serde_json::Value {
    match procedure {
        Retained::Available {
            value: ProcedureObservation::Containing { name },
            ..
        } => serde_json::json!(name),
        Retained::Available {
            value: ProcedureObservation::OutsideProcedure,
            ..
        } => serde_json::Value::Null,
        Retained::Omitted => unavailable_facet(
            "resolve_containing_procedure",
            "Containing procedure observation was omitted.",
            "Retain a procedure observation or provide an explicit address.",
        ),
        Retained::Unavailable {
            reason,
            remediation,
        } => serde_json::json!({
            "state": "unavailable",
            "operation": "resolve_containing_procedure",
            "reason": reason,
            "remediation": remediation,
        }),
    }
}

fn retained_address(address: &Retained<String>) -> Result<serde_json::Value, Failure> {
    match address {
        Retained::Available { value, .. } if !value.is_empty() => Ok(serde_json::json!(value)),
        Retained::Available { .. } => Err(invalid("address observation is empty")),
        Retained::Omitted => Err(invalid("address observation was omitted")),
        Retained::Unavailable {
            reason,
            remediation,
        } => Ok(serde_json::json!({
            "state": "unavailable",
            "operation": "current_address",
            "reason": reason,
            "remediation": remediation,
        })),
    }
}

fn unavailable_facet(operation: &str, reason: &str, remediation: &str) -> serde_json::Value {
    serde_json::json!({
        "state": "unavailable",
        "operation": operation,
        "reason": reason,
        "remediation": remediation,
    })
}

fn available_text<T>(fact: &Retained<T>, field: &str) -> Result<String, Failure>
where
    T: Clone + Into<String>,
{
    match fact {
        Retained::Available { value, .. } => {
            let text: String = value.clone().into();
            if text.is_empty() {
                Err(invalid(&format!("{field} observation is empty")))
            } else {
                Ok(text)
            }
        }
        Retained::Omitted => Err(invalid(&format!("{field} observation was omitted"))),
        Retained::Unavailable { reason, .. } => Err(invalid(&format!(
            "{field} observation is unavailable: {reason}"
        ))),
    }
}

fn validate_requested_document(document: Option<&str>) -> Result<(), Failure> {
    if document.is_some_and(str::is_empty) {
        return Err(invalid("requested_document must not be empty"));
    }
    Ok(())
}

fn validate_source_order(sources: &[SourceObservation]) -> Result<(), Failure> {
    for source in sources {
        if source.operation.is_empty() {
            return Err(invalid("source_order operation must not be empty"));
        }
    }
    Ok(())
}

fn validate_evidence_links(links: &[String]) -> Result<(), Failure> {
    if links.iter().any(String::is_empty) {
        return Err(invalid("evidence_links must not contain empty identifiers"));
    }
    Ok(())
}

fn invalid(message: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide retained current document, address, and procedure observations.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
