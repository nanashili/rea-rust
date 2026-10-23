//! Offline adapter for the packet-capture client inspection contract.
//!
//! The public TypeScript provider resolves caller-selected tshark and
//! capinfos commands and invokes each with --version. This runtime module
//! has no host-process authority, so it accepts the resulting selections and
//! bounded probe output as caller-supplied facts. It never resolves a
//! command, starts a process, or treats client metadata alone as a successful
//! probe.

use rea_application::pcap;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_pcap_client";

/// Inspect a captured packet-capture client observation.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_ref(&input)
}

/// Inspect a captured packet-capture client observation without taking
/// ownership of the caller's JSON value.
pub fn dispatch_ref(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;

    reject_unknown_fields(object)?;
    require_probe(object, "tshark")?;
    require_probe(object, "capinfos")?;

    let result = pcap::client::inspect_value(input)?;
    require_resolved_versions(&result)?;

    Ok(json!({
        "result": result,
        "provenance": {
            "source": "caller-supplied-pcap-client-probes",
            "execution": "none",
        },
    }))
}

fn require_resolved_versions(result: &Value) -> Result<(), Failure> {
    let client = result
        .get("client")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("client result is malformed"))?;

    for tool in ["tshark", "capinfos"] {
        let field = format!("{tool}_version");
        if !client
            .get(&field)
            .is_some_and(|version| version.as_str().is_some_and(|value| !value.is_empty()))
        {
            return Err(Failure::new(
                "configuration_failure",
                "provider_unavailable",
                format!("The selected {tool} command did not report a version."),
                false,
                "Provide usable Wireshark 4.x tshark and capinfos --version output; the runtime does not invoke host tools.".into(),
                BTreeMap::from([
                    ("operation".into(), Detail::Text(OPERATION.into())),
                    ("tool".into(), Detail::Text(tool.into())),
                ]),
            ));
        }
    }

    Ok(())
}

fn require_probe(object: &Map<String, Value>, tool: &str) -> Result<(), Failure> {
    let selection = object
        .get(tool)
        .ok_or_else(|| invalid(&format!("{tool} selection is required")))?;
    if !selection.is_object() {
        return Err(invalid(&format!("{tool} selection must be an object")));
    }

    let output_name = format!("{tool}_output");
    let output = object
        .get(&output_name)
        .ok_or_else(|| invalid(&format!("{output_name} is required")))?;
    if !output.is_object() {
        return Err(invalid(&format!("{output_name} must be an object")));
    }

    Ok(())
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    const ALLOWED: [&str; 4] = ["tshark", "capinfos", "tshark_output", "capinfos_output"];
    if object
        .keys()
        .any(|field| !ALLOWED.contains(&field.as_str()))
    {
        return Err(invalid("input contains an unknown field"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide both caller-selected Wireshark tools and bounded --version output; the runtime does not invoke host tools.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("authority".into(), Detail::Text("caller-supplied-tool-output".into())),
        ]),
    )
}
