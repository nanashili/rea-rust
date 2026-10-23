//! Strings, derived references, instruction listings and byte reads served
//! by the worker's analysis commands.
//!
//! Every page is checked against its declared offset, count and commitment
//! before results are combined, like the inventory reader.
use crate::inventory::Inventory;
use crate::protocol::Procedure;
use crate::selectors;
use crate::session::Session;
use crate::worker::Control;
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// Pinned worker page sizes (`engine().limits`).
pub(crate) const MAX_STRING_PAGE: u64 = 1024;
pub(crate) const MAX_REFERENCE_PAGE: u64 = 4096;
pub(crate) const MAX_INSTRUCTION_PAGE: u64 = 4096;
pub(crate) const MAX_READ_BYTES: u64 = 1024 * 1024;
/// Largest string inventory read into one result.
const MAX_STRINGS: u64 = 4_000_000;
/// References returned by one `xrefs` read before it reports truncation.
const MAX_XREFS: u64 = 100_000;
/// References combined for one procedure relationship read.
const MAX_FUNCTION_REFERENCES: u64 = 1_000_000;

const PROVENANCE: &str = "ghidra-rust-linear-pcode";

/// One saved string.
#[derive(Clone, Debug)]
pub(crate) struct ImageString {
    address: String,
    value: String,
    byte_length: u64,
}

/// One derived reference as the worker reports it.
#[derive(Clone, Debug)]
struct Reference {
    function: String,
    source: String,
    target: Option<String>,
    kind: String,
}

/// Per-client cache of the validated string inventory.
#[derive(Default)]
pub(crate) struct Analysis {
    strings: Mutex<Option<Arc<Vec<ImageString>>>>,
}

fn object<'a>(value: &'a Value) -> Option<&'a Map<String, Value>> {
    value.as_object()
}

fn canonical(text: &str) -> Option<String> {
    let hex = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    if hex.is_empty() || hex.len() > 16 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16)
        .ok()
        .map(|value| format!("0x{value:x}"))
}

fn page_fields(reply: &Value) -> Option<(u64, Option<u64>, u64, &Vec<Value>)> {
    let reply = object(reply)?;
    let offset = reply.get("offset")?.as_u64()?;
    let next = match reply.get("next_offset")? {
        Value::Null => None,
        value => Some(value.as_u64()?),
    };
    let total = reply.get("total")?.as_u64()?;
    let items = reply.get("items")?.as_array()?;
    let end = offset.checked_add(items.len() as u64)?;
    (end <= total && next == (end < total).then_some(end) && !(end < total && items.is_empty()))
        .then_some((offset, next, total, items))
}

fn parse_string(item: &Value) -> Option<ImageString> {
    let item = object(item)?;
    if item.len() != 3 {
        return None;
    }
    let address = item.get("address")?.as_str()?;
    (canonical(address).as_deref() == Some(address)).then_some(())?;
    Some(ImageString {
        address: address.to_owned(),
        value: item.get("value")?.as_str()?.to_owned(),
        byte_length: item.get("byte_length")?.as_u64()?,
    })
}

fn parse_reference(item: &Value) -> Option<Reference> {
    let item = object(item)?;
    if item.len() != 4 {
        return None;
    }
    let field = |key: &str| item.get(key).and_then(Value::as_str).map(str::to_owned);
    let kind = field("kind")?;
    let target = match item.get("target")? {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        _ => return None,
    };
    if target.is_none() != (kind == "indirect_call") {
        return None;
    }
    matches!(
        kind.as_str(),
        "call" | "jump" | "conditional_jump" | "read" | "write" | "address" | "indirect_call"
    )
    .then_some(Reference {
        function: field("function")?,
        source: field("source")?,
        target,
        kind,
    })
}

fn address_input(operation: &str, input: &Map<String, Value>) -> Result<String, AnalysisError> {
    let Some(text) = input.get("address").and_then(Value::as_str) else {
        return Err(AnalysisError::input_message(
            operation,
            "The Ghidra worker requires an explicit hexadecimal address.",
            Vec::new(),
        ));
    };
    canonical(text).ok_or_else(|| {
        AnalysisError::input_message(
            operation,
            "Expected a 0x-prefixed hexadecimal address.",
            Vec::new(),
        )
    })
}

fn capacity(operation: &str, reason: &str, limits: Value) -> AnalysisError {
    AnalysisError::from(ErrorKind::ResourceConstraint {
        operation: operation.to_owned(),
        resource: "capacity".to_owned(),
        reason: reason.to_owned(),
        reported_limits: Some(limits),
        remediation_action: None,
        retryable: Some(false),
    })
}

/// A procedure identity without a recovered body: extents are bounded by
/// the next inventory entry, which is an upper bound, not a function body.
fn identity(procedure: &Procedure) -> Value {
    json!({
        "address": procedure.address,
        "name": procedure.name,
        "classification": null,
        "body": {
            "available": false,
            "reason": "The Ghidra worker does not recover function bodies; its listing extent ends at the next inventory entry.",
        },
    })
}

fn kind_reason(kind: &str) -> String {
    let class = match kind {
        "call" => "direct call",
        "jump" => "unconditional branch to another inventory entry",
        "conditional_jump" => "conditional branch to another inventory entry",
        "read" => "load from a propagated address constant",
        "write" => "store to a propagated address constant",
        _ => "use of a propagated address constant",
    };
    format!(
        "Derived {class} ({PROVENANCE}); Ghidra reference types and operand indexes are not recorded."
    )
}

fn flow_kind(kind: &str) -> bool {
    matches!(kind, "call" | "jump" | "conditional_jump")
}

impl Analysis {
    /// The validated string inventory, read once per client.
    pub(crate) fn strings(
        &self,
        session: &Session,
        control: &Control,
    ) -> Result<Arc<Vec<ImageString>>, AnalysisError> {
        if let Some(strings) = self
            .strings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            return Ok(strings);
        }
        session.prepare(control)?;
        let invalid = || session.failure("The Ghidra worker returned an invalid string page.");
        let mut strings: Vec<ImageString> = Vec::new();
        let mut committed: Option<(u64, Value)> = None;
        let mut offset = 0_u64;
        loop {
            let reply = session.worker.request(
                "strings",
                json!({ "offset": offset, "limit": MAX_STRING_PAGE }),
                Some(control),
            )?;
            let (page_offset, next, total, items) = page_fields(&reply).ok_or_else(invalid)?;
            let digest = reply.get("strings_sha256").cloned().unwrap_or(Value::Null);
            if page_offset != offset
                || total > MAX_STRINGS
                || committed
                    .as_ref()
                    .is_some_and(|known| *known != (total, digest.clone()))
            {
                return Err(invalid());
            }
            committed = Some((total, digest));
            for item in items {
                let string = parse_string(item).ok_or_else(invalid)?;
                if strings.last().is_some_and(|previous| {
                    u64::from_str_radix(&previous.address[2..], 16).unwrap_or(0)
                        >= u64::from_str_radix(&string.address[2..], 16).unwrap_or(0)
                }) {
                    return Err(invalid());
                }
                strings.push(string);
            }
            match next {
                None => break,
                Some(next) => offset = next,
            }
        }
        let strings = Arc::new(strings);
        *self
            .strings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::clone(&strings));
        Ok(strings)
    }

    pub(crate) fn list_strings(
        &self,
        session: &Session,
        control: &Control,
    ) -> Result<Value, AnalysisError> {
        Ok(Value::Array(
            self.strings(session, control)?
                .iter()
                .map(string_json)
                .collect(),
        ))
    }

    pub(crate) fn search_strings(
        &self,
        session: &Session,
        input: &Map<String, Value>,
        control: &Control,
    ) -> Result<Value, AnalysisError> {
        let pattern = input
            .get("pattern")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let case_sensitive = input.get("case_sensitive") == Some(&Value::Bool(true));
        let matcher: Box<dyn Fn(&str) -> bool> =
            if input.get("mode").and_then(Value::as_str) == Some("regex") {
                let expression = regex::RegexBuilder::new(pattern)
                    .case_insensitive(!case_sensitive)
                    .size_limit(1 << 24)
                    .build()
                    .map_err(|error| {
                        AnalysisError::input_message(
                            "search_strings",
                            format!("Invalid regular expression: {error}"),
                            Vec::new(),
                        )
                    })?;
                Box::new(move |text: &str| expression.is_match(text))
            } else if case_sensitive {
                let pattern = pattern.to_owned();
                Box::new(move |text: &str| text.contains(&pattern))
            } else {
                let pattern = pattern.to_lowercase();
                Box::new(move |text: &str| text.to_lowercase().contains(&pattern))
            };
        Ok(Value::Array(
            self.strings(session, control)?
                .iter()
                .filter(|string| matcher(&string.value))
                .map(string_json)
                .collect(),
        ))
    }
}

fn string_json(string: &ImageString) -> Value {
    json!({
        "address": string.address,
        "value": string.value,
        "string": {
            "encoding": "UTF-8",
            "encoding_status": "inferred",
            "termination": "present_or_not_required",
            "byte_length": string.byte_length,
        },
    })
}

/// Every reference page for one worker query, up to `maximum`.
fn references(
    session: &Session,
    method: &str,
    address: &str,
    maximum: u64,
    control: &Control,
) -> Result<(Vec<Reference>, bool), AnalysisError> {
    let ready = session.prepare(control)?;
    let invalid = || session.failure("The Ghidra worker returned an invalid reference page.");
    let mut collected = Vec::new();
    let mut offset = 0_u64;
    let mut expected: Option<u64> = None;
    loop {
        let reply = session.worker.request(
            method,
            json!({ "address": address, "offset": offset, "limit": MAX_REFERENCE_PAGE }),
            Some(control),
        )?;
        let (page_offset, next, total, items) = page_fields(&reply).ok_or_else(invalid)?;
        if page_offset != offset
            || expected.is_some_and(|known| known != total)
            || reply.get("inventory_sha256").and_then(Value::as_str)
                != ready.inventory_sha256.as_deref()
        {
            return Err(invalid());
        }
        expected = Some(total);
        for item in items {
            collected.push(parse_reference(item).ok_or_else(invalid)?);
        }
        match next {
            Some(next) if (collected.len() as u64) < maximum => offset = next,
            Some(_) => return Ok((collected, true)),
            None => return Ok((collected, false)),
        }
    }
}

/// Resolve a caller procedure selector to its inventory row.
fn procedure(
    session: &Session,
    inventory: &Inventory,
    operation: &str,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<(Procedure, Arc<Vec<Procedure>>), AnalysisError> {
    let selector = input
        .get("procedure")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let page = selectors::resolve_page(session, &[selector.to_owned()], control, operation)?;
    let Some(item) = page.first() else {
        return Err(session.failure("The worker omitted a selector result."));
    };
    let (Some(address), Some(name)) = (&item.address, &item.name) else {
        return Err(selectors::selector_error(
            operation,
            item.status,
            control.selector_from_provider,
        ));
    };
    let procedures = inventory.read(session, control)?;
    Ok((
        Procedure {
            address: address.clone(),
            name: name.clone(),
        },
        procedures,
    ))
}

fn inventory_row<'a>(procedures: &'a [Procedure], address: &str) -> Option<&'a Procedure> {
    let key = u64::from_str_radix(address.get(2..)?, 16).ok()?;
    procedures
        .binary_search_by_key(&key, |procedure| {
            u64::from_str_radix(&procedure.address[2..], 16).unwrap_or(0)
        })
        .ok()
        .map(|index| &procedures[index])
}

/// One read's result plus caller/callee coverage and truncation facts.
pub(crate) struct Read {
    pub result: Value,
    pub relationship_coverage: Option<Value>,
    pub references_truncated: Option<bool>,
}

impl Read {
    fn plain(result: Value) -> Self {
        Self {
            result,
            relationship_coverage: None,
            references_truncated: None,
        }
    }
}

pub(crate) fn xrefs(
    session: &Session,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<Read, AnalysisError> {
    let address = address_input("xrefs", input)?;
    let (items, truncated) = references(session, "references_to", &address, MAX_XREFS, control)?;
    let sources: BTreeSet<u64> = items
        .iter()
        .filter_map(|item| u64::from_str_radix(item.source.get(2..)?, 16).ok())
        .collect();
    Ok(Read {
        result: json!(
            sources
                .iter()
                .map(|source| format!("0x{source:x}"))
                .collect::<Vec<_>>()
        ),
        relationship_coverage: None,
        references_truncated: Some(truncated),
    })
}

fn relationship(
    session: &Session,
    inventory: &Inventory,
    operation: &str,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<Read, AnalysisError> {
    let (procedure, _) = self::procedure(session, inventory, operation, input, control)?;
    let callers = operation == "procedure_callers";
    let method = if callers {
        "references_to"
    } else {
        "references_from"
    };
    let (items, truncated) = references(
        session,
        method,
        &procedure.address,
        MAX_FUNCTION_REFERENCES,
        control,
    )?;
    if truncated {
        return Err(capacity(
            operation,
            "The procedure has more derived references than one read admits.",
            json!({ "maximum_references": MAX_FUNCTION_REFERENCES }),
        ));
    }
    let mut related = BTreeSet::new();
    let mut indirect = 0_u64;
    for item in &items {
        if item.kind == "indirect_call" {
            indirect += 1;
            continue;
        }
        if !flow_kind(&item.kind) {
            continue;
        }
        let address = if callers {
            Some(&item.function)
        } else {
            item.target.as_ref()
        };
        if let Some(value) = address.and_then(|text| u64::from_str_radix(text.get(2..)?, 16).ok()) {
            related.insert(value);
        }
    }
    let direction = if callers { "callers" } else { "callees" };
    let mut limitations = vec![format!(
        "{} are derived from direct calls and branches to inventory entries found by a linear p-code pass over each function's extent; indirect calls, calls through memory and code outside inventory extents are not resolved.",
        if callers { "Callers" } else { "Callees" }
    )];
    if !callers && indirect > 0 {
        limitations.push(format!(
            "{indirect} indirect call sites in this function have unresolved targets."
        ));
    }
    Ok(Read {
        result: json!(
            related
                .iter()
                .map(|value| format!("0x{value:x}"))
                .collect::<Vec<_>>()
        ),
        relationship_coverage: Some(json!({
            "status": "partial",
            "limitations": limitations,
            "limited_directions": [direction],
            "diagnostics": [
                format!("Derived by {PROVENANCE}."),
                format!("{indirect} indirect call sites with unresolved targets."),
            ],
        })),
        references_truncated: None,
    })
}

pub(crate) fn callers(
    session: &Session,
    inventory: &Inventory,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<Read, AnalysisError> {
    relationship(session, inventory, "procedure_callers", input, control)
}

pub(crate) fn callees(
    session: &Session,
    inventory: &Inventory,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<Read, AnalysisError> {
    relationship(session, inventory, "procedure_callees", input, control)
}

pub(crate) fn procedure_references(
    session: &Session,
    inventory: &Inventory,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<Read, AnalysisError> {
    let (procedure, procedures) =
        self::procedure(session, inventory, "procedure_references", input, control)?;
    let incoming = input.get("direction").and_then(Value::as_str) == Some("incoming");
    let method = if incoming {
        "references_to"
    } else {
        "references_from"
    };
    let (items, truncated) = references(
        session,
        method,
        &procedure.address,
        MAX_FUNCTION_REFERENCES,
        control,
    )?;
    if truncated {
        return Err(capacity(
            "procedure_references",
            "The procedure has more derived references than one read admits.",
            json!({ "maximum_references": MAX_FUNCTION_REFERENCES }),
        ));
    }
    let row = |address: &str| {
        inventory_row(&procedures, address)
            .map(identity)
            .unwrap_or(Value::Null)
    };
    let mut references = Vec::new();
    let mut unresolved = Vec::new();
    for item in &items {
        let Some(target) = &item.target else {
            unresolved.push(json!({
                "address": item.source,
                "reason": "Indirect call target is not resolved by the Ghidra worker.",
            }));
            continue;
        };
        references.push(json!({
            "source_address": item.source,
            "target_address": target,
            "source_procedure": row(&item.function),
            "target_procedure": row(target),
            "kind": { "available": false, "reason": kind_reason(&item.kind) },
        }));
    }
    Ok(Read::plain(json!({
        "procedure": identity(&procedure),
        "direction": if incoming { "incoming" } else { "outgoing" },
        "reference_kinds_available": false,
        "unresolved_calls": unresolved,
        "references": references,
    })))
}

/// Every listed instruction of one procedure and why the listing stopped.
fn listing(
    session: &Session,
    address: &str,
    control: &Control,
) -> Result<(Vec<String>, String), AnalysisError> {
    session.prepare(control)?;
    let invalid = || session.failure("The Ghidra worker returned an invalid instruction page.");
    let mut lines = Vec::new();
    let mut offset = 0_u64;
    loop {
        let reply = session.worker.request(
            "instructions",
            json!({ "address": address, "offset": offset, "limit": MAX_INSTRUCTION_PAGE }),
            Some(control),
        )?;
        let reply = object(&reply).ok_or_else(invalid)?;
        let items = reply
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        for item in items {
            let item = object(item).ok_or_else(invalid)?;
            let field = |key: &str| item.get(key).and_then(Value::as_str).ok_or_else(invalid);
            let operands = field("operands")?;
            lines.push(if operands.is_empty() {
                format!("{}: {}", field("address")?, field("mnemonic")?)
            } else {
                format!("{}: {} {}", field("address")?, field("mnemonic")?, operands)
            });
        }
        match reply.get("next_offset") {
            Some(Value::Number(next)) => offset = next.as_u64().ok_or_else(invalid)?,
            Some(Value::Null) => {
                let stop = reply
                    .get("stop")
                    .and_then(Value::as_str)
                    .ok_or_else(invalid)?;
                return Ok((lines, stop.to_owned()));
            }
            _ => return Err(invalid()),
        }
    }
}

fn stop_limitation(stop: &str) -> String {
    match stop {
        "next_entry" => "The listing is linear from the entry to the next inventory entry; it is not a recovered function body.".to_owned(),
        "end_of_code" => "The listing stopped at the end of the executable section.".to_owned(),
        "instruction_limit" => "The listing stopped at the 65,536-instruction cap.".to_owned(),
        _ => "The listing stopped at bytes the engine could not decode.".to_owned(),
    }
}

pub(crate) fn assembly(
    session: &Session,
    inventory: &Inventory,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<Read, AnalysisError> {
    let (procedure, _) = self::procedure(session, inventory, "procedure_assembly", input, control)?;
    let (lines, _) = listing(session, &procedure.address, control)?;
    Ok(Read::plain(json!(lines.join("\n"))))
}

pub(crate) fn instructions(
    session: &Session,
    inventory: &Inventory,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<Read, AnalysisError> {
    let (procedure, _) = self::procedure(
        session,
        inventory,
        "read_function_instructions",
        input,
        control,
    )?;
    let (lines, stop) = listing(session, &procedure.address, control)?;
    Ok(Read::plain(json!({
        "procedure": identity(&procedure),
        "instructions": lines,
        "limitations": [stop_limitation(&stop)],
    })))
}

pub(crate) fn read_bytes(
    session: &Session,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<Read, AnalysisError> {
    let address = address_input("read_bytes", input)?;
    let length = input.get("length").and_then(Value::as_u64).unwrap_or(256);
    if length > MAX_READ_BYTES {
        return Err(capacity(
            "read_bytes",
            "The Ghidra worker reads at most 1 MiB per request.",
            json!({ "maximum_bytes": MAX_READ_BYTES }),
        ));
    }
    session.prepare(control)?;
    let reply = session.worker.request(
        "read_bytes",
        json!({ "address": address, "length": length }),
        Some(control),
    )?;
    let invalid = || session.failure("The Ghidra worker returned an invalid byte read.");
    let reply = object(&reply).ok_or_else(invalid)?;
    let hex = reply
        .get("bytes_hex")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let returned = reply
        .get("returned_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    if hex.len() as u64 != returned * 2
        || returned > length
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    Ok(Read::plain(json!({
        "address": address,
        "requested_bytes": length,
        "returned_bytes": returned,
        "bytes_hex": hex,
        "complete": returned == length,
    })))
}
