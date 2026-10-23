//! Native DOM listener descriptors without evaluating JavaScript or invoking
//! handlers (`src/browser/execution/CdpEventListeners.ts` and
//! `CdpListenerSelector.ts`).
use super::iso_now;
use super::protocol::{self, integer};
use super::session::RuntimeSession;
use super::sources::{ReadEvents, Sources};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_host::cdp_transport::CdpTransportError;
use serde_json::{Value, json};

const LIMITATIONS: [&str; 5] = [
    "Inspects listeners registered directly on the first native CSS match in the selected main document. Delegated ancestor listeners, descendants, closed shadow roots and framework registries are not enumerated.",
    "Native CDP listener descriptors report callback locations; registration time, dispatch history and UI causality remain unknown. REA does not dispatch an event, evaluate JavaScript or invoke a handler.",
    "Source identity uses this session's script ID and proven main-frame default-world metadata. Isolated or unknown worlds cannot establish website callback/source joins. A URL or sourceURL declaration never establishes identity or execution.",
    "Source text is retained inline with its independently computed UTF-8 digest; the producer hash is preserved separately. Missing source ownership or collected scripts remain explicit.",
    "REA releases its remote object group, disables enabled domains and detaches its transport; the externally owned page remains open.",
];

/// `eventListenerObjectGroup`: an owned remote object namespace.
pub(super) fn object_group() -> String {
    let mut bytes = [0_u8; 16];
    let seed = format!(
        "{:?}{:?}{}",
        std::time::SystemTime::now(),
        std::thread::current().id(),
        std::process::id()
    );
    use sha2::{Digest, Sha256};
    bytes.copy_from_slice(&Sha256::digest(seed.as_bytes())[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "rea-listeners-{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn command(
    session: &mut RuntimeSession<'_>,
    sources: &mut Sources,
    method: &str,
    params: Value,
) -> Result<Value, AnalysisError> {
    let result = session.command(method, params);
    pump(session, sources);
    result
}

fn pump(session: &mut RuntimeSession<'_>, sources: &mut Sources) {
    let (events, overflowed) = session.take_events();
    if overflowed {
        sources.fail(AnalysisError::output(
            session.operation,
            "Context/script metadata exceeds the complete 8 MiB event budget.",
        ));
    }
    for event in &events {
        sources.ingest(event, true);
    }
}

fn malformed(operation: &str, method: &str) -> AnalysisError {
    AnalysisError::output(operation, format!("Malformed {method} result."))
}

/// `queryListenerSelector`: classify Chromium's selector syntax rejection.
fn query_selector(
    session: &mut RuntimeSession<'_>,
    sources: &mut Sources,
    node_id: u64,
    selector: &str,
) -> Result<Value, AnalysisError> {
    let result = session.command_raw(
        "DOM.querySelector",
        json!({ "nodeId": node_id, "selector": selector }),
    );
    pump(session, sources);
    match result {
        Ok(value) => Ok(value),
        Err(CdpTransportError::Protocol {
            code: Some(-32000),
            message,
        }) if message == "DOM Error while querying" => {
            let rejection = session.classify(
                CdpTransportError::Protocol {
                    code: Some(-32000),
                    message,
                },
                "DOM.querySelector",
            );
            Err(AnalysisError::input(
                session.operation,
                vec![InputIssue {
                    path: vec![json!("selector")],
                    reason: "invalid_format",
                    message: Some(format!(
                        "Chromium rejected the CSS selector syntax for target {}: {selector}. {}",
                        session.target.target_id,
                        rejection.user_message()
                    )),
                    expected: None,
                    minimum: None,
                    maximum: None,
                }],
            ))
        }
        Err(error) => Err(session.classify(error, "DOM.querySelector")),
    }
}

/// `captureWebEventListeners`.
pub(super) fn capture(
    session: &mut RuntimeSession<'_>,
    selector: &str,
    group: &str,
) -> Result<Value, AnalysisError> {
    let operation = session.operation;
    session.begin_completion();
    let mut sources = Sources::new(session);
    for domain in ["Page", "Runtime", "Debugger", "DOM"] {
        let result = session.enable(domain);
        pump(session, &mut sources);
        result?;
    }
    let asserted = session.assert_document();
    pump(session, &mut sources);
    asserted?;
    let document = command(
        session,
        &mut sources,
        "DOM.getDocument",
        json!({ "depth": 0 }),
    )?;
    let root = document
        .get("root")
        .and_then(|root| root.get("nodeId"))
        .and_then(integer)
        .filter(|id| *id >= 1)
        .ok_or_else(|| malformed(operation, "DOM.getDocument"))?;
    let selected = query_selector(session, &mut sources, root, selector)?;
    let node_id = selected
        .get("nodeId")
        .and_then(integer)
        .ok_or_else(|| malformed(operation, "DOM.querySelector"))?;
    let mut backend_node_id = None;
    let mut descriptors = Vec::new();
    if node_id != 0 {
        let described = command(
            session,
            &mut sources,
            "DOM.describeNode",
            json!({ "nodeId": node_id }),
        )?;
        backend_node_id = Some(
            described
                .get("node")
                .and_then(|node| node.get("backendNodeId"))
                .and_then(integer)
                .filter(|id| *id >= 1)
                .ok_or_else(|| malformed(operation, "DOM.describeNode"))?,
        );
        let resolved = command(
            session,
            &mut sources,
            "DOM.resolveNode",
            json!({ "nodeId": node_id, "objectGroup": group }),
        )?;
        let object_id = resolved
            .get("object")
            .and_then(|object| object.get("objectId"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| malformed(operation, "DOM.resolveNode"))?
            .to_owned();
        let listeners = command(
            session,
            &mut sources,
            "DOMDebugger.getEventListeners",
            json!({ "objectId": object_id, "depth": 0, "pierce": false }),
        )?;
        descriptors = protocol::listeners(&listeners)
            .ok_or_else(|| malformed(operation, "DOMDebugger.getEventListeners"))?;
    }
    let ids: Vec<String> = descriptors
        .iter()
        .map(|listener| listener.script_id.clone())
        .filter(|id| !id.is_empty())
        .collect();
    let retained = sources.read(session, &ids, ReadEvents::Ingest)?;
    let asserted = session.assert_document();
    pump(session, &mut sources);
    asserted?;
    sources.check()?;
    let listeners: Vec<Value> = descriptors
        .iter()
        .map(|listener| {
            let url = sources.scripts.get(&listener.script_id).map(|script| script.url.clone());
            json!({
                "type": listener.kind,
                "use_capture": listener.use_capture,
                "passive": listener.passive,
                "once": listener.once,
                "location": sources.location(&listener.script_id, url.as_deref(), listener.line, Some(listener.column), None),
                "execution": "unknown",
            })
        })
        .collect();
    Ok(json!({
        "browser": session.discovery.version,
        "target": session.target.to_json(),
        "inspected_at": iso_now(),
        "selected_node": {
            "selector": selector,
            "match": if node_id == 0 { "not_found" } else { "found" },
            "backend_node_id": backend_node_id,
        },
        "listeners": listeners,
        "sources": retained,
        "cleanup": "confirmed",
        "limitations": LIMITATIONS,
    }))
}
