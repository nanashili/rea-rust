//! Bounded native value tracing over caller-supplied analysis Evidence.
//!
//! The TypeScript implementation executes `analyze_function` and
//! `resolve_native_call_targets` as it discovers procedures.  The native
//! boundary receives those authenticated records from its adapter instead.
//! This module therefore only composes already observed p-code facts; it
//! never executes a target or treats a missing fact as a negative result.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const OPERATION: &str = "trace_native_values";
const MAX_NODE_BYTES: usize = 8 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
struct Function<'a> {
    evidence: &'a Value,
    evidence_id: String,
    address: String,
    flow: Option<&'a Value>,
    limitations: Vec<String>,
}

#[derive(Clone)]
struct CallTarget {
    target: String,
    status: String,
    procedure: Option<String>,
    limitations: Vec<String>,
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("trace_native_values input must be an object"))?;
    const FIELDS: &[&str] = &[
        "procedure",
        "functions",
        "call_targets",
        "max_depth",
        "max_functions",
        "max_call_sites",
        "max_nodes",
        "max_edges",
        "offset",
        "limit",
    ];
    if let Some(field) = object
        .keys()
        .find(|field| !FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!("unknown input field: {field}")));
    }
    let procedure = object
        .get("procedure")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("procedure is required"))?;
    let _ = procedure;
    let functions = object
        .get("functions")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("functions must be a non-empty Evidence array"))?;
    if functions.is_empty() || functions.len() > 64 {
        return Err(invalid("functions count is outside the supported bound"));
    }
    for (index, function) in functions.iter().enumerate() {
        if function.get("operation").and_then(Value::as_str) != Some("analyze_function") {
            return Err(invalid(&format!(
                "functions[{index}] is not analyze_function Evidence"
            )));
        }
    }
    validate_bound(object, "max_depth", 16, false)?;
    validate_bound(object, "max_functions", 64, true)?;
    validate_bound(object, "max_call_sites", 4096, true)?;
    validate_bound(object, "max_nodes", 20_000, true)?;
    validate_bound(object, "max_edges", 40_000, true)?;
    validate_bound(object, "limit", 5_000, true)?;
    if let Some(offset) = object.get("offset") {
        if !offset.is_u64() {
            return Err(invalid("offset must be a non-negative integer"));
        }
    }
    Ok(())
}

pub fn trace(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let functions = input
        .get("functions")
        .and_then(Value::as_array)
        .expect("validated functions");
    let records = parse_functions(functions)?;
    let call_targets = parse_call_targets(input.get("call_targets"))?;
    let seed = input
        .get("procedure")
        .and_then(Value::as_str)
        .expect("validated procedure");
    let max_depth = number(input, "max_depth", 3);
    let max_functions = number(input, "max_functions", 16);
    let max_call_sites = number(input, "max_call_sites", 256);
    let max_nodes = number(input, "max_nodes", 5_000);
    let max_edges = number(input, "max_edges", 10_000);
    let offset = number(input, "offset", 0);
    let limit = number(input, "limit", 1_000);

    let mut queue = VecDeque::from([(seed.to_owned(), 0usize)]);
    let mut visited = BTreeSet::new();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut procedures = Vec::new();
    let mut unknowns = Vec::new();
    let mut pending_bindings = Vec::new();
    let mut limitations = BTreeSet::from([
        "Static decompiler def-use graphs cover recovered block members; when membership is unavailable they exclude operations marked dead. Logical CALL argument positions bind to recovered HighParam ordinals and RETURN values bind to recovered CALL outputs; these are decompiler-derived dependencies, not original source or runtime observations. Missing parameters, variadic arguments and alias dependencies remain unknown.".to_owned(),
        "LOAD and STORE are memory operations; object fields, persistent state and RNG semantics are not inferred from names or pseudocode.".to_owned(),
    ]);
    let mut call_sites = 0usize;
    let mut decompilations = 0usize;
    let mut node_bytes = 0usize;
    let mut truncated = false;

    while let Some((requested, depth)) = queue.pop_front() {
        if visited.contains(&requested) {
            continue;
        }
        if decompilations >= max_functions {
            truncated = true;
            unknowns.push(json!({"procedure": requested, "address": Value::Null, "reason": "decompilation budget reached"}));
            break;
        }
        let Some(function) = find_function(&records, &requested) else {
            unknowns.push(json!({"procedure": requested, "address": Value::Null, "reason": "No analyze_function Evidence covers this procedure"}));
            continue;
        };
        decompilations += 1;
        visited.insert(requested.clone());
        visited.insert(function.address.clone());
        limitations.extend(function.limitations.iter().cloned());
        let profile = function
            .evidence
            .pointer("/analysis_profile/digest")
            .cloned()
            .unwrap_or(Value::Null);
        procedures.push(json!({"address":function.address,"depth":depth,"evidence_id":function.evidence_id,"provider":function.evidence.pointer("/provider/id").and_then(Value::as_str).unwrap_or("unknown"),"analysis_profile_digest":profile}));
        let Some(flow) = function.flow else {
            unknowns.push(json!({"procedure":function.address,"address":Value::Null,"reason":"Provider has no native def-use model"}));
            continue;
        };
        if flow.get("available") != Some(&Value::Bool(true)) {
            unknowns.push(json!({"procedure":function.address,"address":Value::Null,"reason":flow.get("reason").and_then(Value::as_str).unwrap_or("native value flow unavailable")}));
            continue;
        }
        if flow.get("truncated") == Some(&Value::Bool(true)) {
            truncated = true;
            unknowns.push(json!({"procedure":function.address,"address":Value::Null,"reason":"Provider p-code was truncated"}));
        }
        let operation_ids = flow
            .get("operations")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.get("id").and_then(Value::as_str))
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let mut local_ids = BTreeSet::new();
        let mut parameter_ids = BTreeMap::new();
        for operation in flow
            .get("operations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if operation.get("block_membership").and_then(Value::as_str) == Some("detached")
                || (operation.get("block_membership").and_then(Value::as_str)
                    == Some("unavailable")
                    && operation.get("is_dead") == Some(&Value::Bool(true)))
            {
                continue;
            }
            let Some(id) = operation.get("id").and_then(Value::as_str) else {
                continue;
            };
            let node = json!({"id":format!("{}/{}", function.address, id),"procedure":function.address,"evidence_id":function.evidence_id,"kind":"operation","operation":operation,"parameter":Value::Null});
            if !retain_node(&mut nodes, &node, max_nodes, &mut node_bytes) {
                truncated = true;
                break;
            }
            local_ids.insert(id.to_owned());
            if operation
                .get("opcode")
                .and_then(Value::as_str)
                .is_some_and(|opcode| opcode == "CALL" || opcode == "CALLIND")
            {
                if call_sites >= max_call_sites {
                    truncated = true;
                    unknowns.push(json!({"procedure":function.address,"address":operation.get("address"),"reason":"Call-site resolution budget reached"}));
                    continue;
                }
                call_sites += 1;
                let call = format!("{}/{}", function.address, id);
                let targets = call_targets
                    .get(
                        operation
                            .get("address")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    )
                    .cloned()
                    .unwrap_or_default();
                if targets.is_empty() {
                    unknowns.push(json!({"procedure":function.address,"address":operation.get("address"),"reason":"Call target unavailable"}));
                }
                for target in targets {
                    limitations.extend(target.limitations.iter().cloned());
                    if !retain_edge(
                        &mut edges,
                        json!({"source":call,"target":target.target,"input_index":Value::Null,"kind":"call","status":target.status,"evidence_id":function.evidence_id}),
                        max_edges,
                    ) {
                        truncated = true;
                        break;
                    }
                    if target.status != "candidate" {
                        let destination = target.procedure.unwrap_or_else(|| target.target.clone());
                        if depth < max_depth {
                            queue.push_back((destination.clone(), depth + 1));
                        } else {
                            truncated = true;
                            unknowns.push(json!({"procedure":function.address,"address":operation.get("address"),"reason":"Call depth budget reached"}));
                        }
                        pending_bindings.push((
                            function.address.clone(),
                            call.clone(),
                            destination,
                            operation.clone(),
                            function.evidence_id.clone(),
                        ));
                    } else {
                        truncated = true;
                        unknowns.push(json!({"procedure":function.address,"address":operation.get("address"),"reason":"Ambiguous call candidates were not traversed"}));
                    }
                }
            }
        }
        for parameter in flow
            .get("parameters")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(ordinal) = parameter.get("ordinal").and_then(Value::as_u64) else {
                continue;
            };
            let mut local = format!("parameter:{ordinal}");
            let mut suffix = 1;
            while operation_ids.contains(local.as_str()) {
                local = format!("parameter:{ordinal}#{suffix}");
                suffix += 1;
            }
            let id = format!("{}/{}", function.address, local);
            let node = json!({"id":id,"procedure":function.address,"evidence_id":function.evidence_id,"kind":"parameter","operation":Value::Null,"parameter":parameter});
            if !retain_node(&mut nodes, &node, max_nodes, &mut node_bytes) {
                truncated = true;
                break;
            }
            parameter_ids.insert(ordinal, id);
        }
        for use_item in flow
            .get("parameter_uses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(source) = parameter_ids.get(
                &use_item
                    .get("ordinal")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX),
            ) else {
                continue;
            };
            let Some(use_id) = use_item.get("use").and_then(Value::as_str) else {
                continue;
            };
            if !local_ids.contains(use_id) {
                continue;
            }
            if !retain_edge(
                &mut edges,
                json!({"source":source,"target":format!("{}/{}",function.address,use_id),"input_index":use_item.get("input_index"),"kind":"parameter-use","status":"derived","evidence_id":function.evidence_id}),
                max_edges,
            ) {
                truncated = true;
                break;
            }
        }
        for relation in flow
            .get("def_use")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(definition) = relation.get("definition").and_then(Value::as_str) else {
                continue;
            };
            let Some(use_id) = relation.get("use").and_then(Value::as_str) else {
                continue;
            };
            if !local_ids.contains(definition) || !local_ids.contains(use_id) {
                continue;
            }
            if !retain_edge(
                &mut edges,
                json!({"source":format!("{}/{}",function.address,definition),"target":format!("{}/{}",function.address,use_id),"input_index":relation.get("input_index"),"kind":"def-use","status":"derived","evidence_id":function.evidence_id}),
                max_edges,
            ) {
                truncated = true;
                break;
            }
        }
    }
    add_bindings(
        &mut edges,
        &mut unknowns,
        &pending_bindings,
        &nodes,
        max_edges,
        &mut truncated,
    );
    let total_edges = edges.len();
    let page = nodes
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let page_ids = page
        .iter()
        .filter_map(|node| node.get("id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let page_edges = edges
        .into_iter()
        .filter(|edge| {
            edge.get("source")
                .and_then(Value::as_str)
                .is_some_and(|source| page_ids.contains(source))
        })
        .collect::<Vec<_>>();
    let next_offset = if offset + page.len() < nodes.len() {
        Some(offset + page.len())
    } else {
        None
    };
    let result = json!({"seed":seed,"target_sha256":target_digest(&records)?,"nodes":page,"edges":page_edges,"procedures":procedures,"unknowns":unknowns,"total_nodes":nodes.len(),"total_edges":total_edges,"decompilations":decompilations,"next_offset":next_offset,"truncated":truncated || page.len() != nodes.len(),"limitations":limitations.into_iter().collect::<Vec<_>>()});
    if serde_json::to_vec(&result)
        .map(|bytes| bytes.len())
        .unwrap_or(MAX_OUTPUT_BYTES + 1)
        > MAX_OUTPUT_BYTES
    {
        return Err(invalid(
            "Graph output exceeds 32 MiB; lower max_nodes, max_edges or page limit",
        ));
    }
    Ok(result)
}

fn parse_functions<'a>(items: &'a [Value]) -> Result<Vec<Function<'a>>, Failure> {
    let mut output = Vec::new();
    for item in items {
        let evidence_id = item
            .get("evidence_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("Function Evidence must include evidence_id"))?
            .to_owned();
        let result = item
            .get("normalized_result")
            .or_else(|| item.get("result"))
            .ok_or_else(|| invalid("Function Evidence must include normalized_result"))?;
        let dossier = result.get("dossier").unwrap_or(result);
        let procedure = dossier
            .get("procedure")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("Function Evidence dossier must include procedure"))?;
        let address = procedure
            .get("address")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("Function procedure address is required"))?
            .to_owned();
        let flow = dossier
            .get("native_value_flow")
            .filter(|value| !value.is_null());
        let mut limitations = strings(item.get("limitations"));
        limitations.extend(strings(dossier.get("limitations")));
        limitations.sort();
        limitations.dedup();
        output.push(Function {
            evidence: item,
            evidence_id,
            address,
            flow,
            limitations,
        });
    }
    Ok(output)
}

fn parse_call_targets(value: Option<&Value>) -> Result<BTreeMap<String, Vec<CallTarget>>, Failure> {
    let mut output = BTreeMap::new();
    for item in value.and_then(Value::as_array).into_iter().flatten() {
        if item.get("operation").and_then(Value::as_str) != Some("resolve_native_call_targets") {
            return Err(invalid(
                "call_targets must be resolve_native_call_targets Evidence",
            ));
        }
        let result = item
            .get("normalized_result")
            .or_else(|| item.get("result"))
            .unwrap_or(item);
        let call_site = result
            .get("call_site")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        for target in result
            .get("targets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(address) = target.get("address").and_then(Value::as_str) {
                output
                    .entry(call_site.clone())
                    .or_insert_with(Vec::new)
                    .push(CallTarget {
                        target: address.to_owned(),
                        status: target
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("candidate")
                            .to_owned(),
                        procedure: target
                            .get("procedure")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        limitations: strings(
                            item.get("limitations")
                                .or_else(|| result.get("limitations")),
                        ),
                    });
            }
        }
    }
    Ok(output)
}

fn add_bindings(
    edges: &mut Vec<Value>,
    unknowns: &mut Vec<Value>,
    bindings: &[(String, String, String, Value, String)],
    nodes: &[Value],
    max_edges: usize,
    truncated: &mut bool,
) {
    for (caller, call, callee, operation, evidence_id) in bindings {
        let parameters = nodes
            .iter()
            .filter(|node| {
                node.get("procedure").and_then(Value::as_str) == Some(callee)
                    && node.get("kind").and_then(Value::as_str) == Some("parameter")
            })
            .collect::<Vec<_>>();
        if parameters.is_empty() {
            unknowns.push(json!({"procedure":caller,"address":Value::Null,"reason":format!("Parameter bindings for {callee} are unavailable or omitted")}));
        }
        let argument_count = operation
            .get("inputs")
            .and_then(Value::as_array)
            .map_or(0, |items| items.len().saturating_sub(1));
        for parameter in parameters {
            let ordinal = parameter
                .pointer("/parameter/ordinal")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX);
            if ordinal as usize >= argument_count {
                unknowns.push(json!({"procedure":caller,"address":Value::Null,"reason":format!("Argument {ordinal} for {callee} was not recovered")}));
                continue;
            }
            if !retain_edge(
                edges,
                json!({"source":call,"target":parameter.get("id"),"input_index":ordinal + 1,"kind":"argument-binding","status":"derived","evidence_id":evidence_id}),
                max_edges,
            ) {
                *truncated = true;
                break;
            }
        }
        if operation
            .get("output")
            .is_some_and(|value| !value.is_null())
        {
            for node in nodes.iter().filter(|node| {
                node.get("procedure").and_then(Value::as_str) == Some(callee)
                    && node.pointer("/operation/opcode").and_then(Value::as_str) == Some("RETURN")
            }) {
                if !retain_edge(
                    edges,
                    json!({"source":node.get("id"),"target":call,"input_index":1,"kind":"return-binding","status":"derived","evidence_id":node.get("evidence_id")}),
                    max_edges,
                ) {
                    *truncated = true;
                    break;
                }
            }
        }
    }
}

fn retain_node(nodes: &mut Vec<Value>, node: &Value, max_nodes: usize, bytes: &mut usize) -> bool {
    if nodes.len() >= max_nodes {
        return false;
    }
    let size = serde_json::to_vec(node).map_or(usize::MAX, |value| value.len());
    if size > MAX_NODE_BYTES.saturating_sub(*bytes) {
        return false;
    }
    *bytes += size;
    nodes.push(node.clone());
    true
}
fn retain_edge(edges: &mut Vec<Value>, edge: Value, max_edges: usize) -> bool {
    if edges.len() >= max_edges {
        false
    } else {
        edges.push(edge);
        true
    }
}
fn find_function<'a>(functions: &'a [Function<'a>], requested: &str) -> Option<&'a Function<'a>> {
    functions.iter().find(|function| {
        function.address == requested
            || function
                .evidence
                .pointer("/normalized_result/dossier/procedure/name")
                .and_then(Value::as_str)
                == Some(requested)
    })
}
fn target_digest(functions: &[Function<'_>]) -> Result<Value, Failure> {
    let mut digest = None;
    for function in functions {
        let current = function
            .evidence
            .pointer("/subject/digest/sha256")
            .cloned()
            .or_else(|| function.evidence.pointer("/subject/sha256").cloned());
        if let Some(current) = current {
            if digest
                .as_ref()
                .is_some_and(|known: &Value| known != &current)
            {
                return Err(invalid("Cross-function target digest mismatch"));
            }
            digest = Some(current);
        }
    }
    digest.ok_or_else(|| invalid("Function Evidence must include an artifact SHA-256 digest"))
}
fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
fn number(input: &Value, name: &str, default: usize) -> usize {
    input
        .get(name)
        .and_then(Value::as_u64)
        .map_or(default, |value| value as usize)
}
fn validate_bound(
    object: &serde_json::Map<String, Value>,
    name: &str,
    maximum: u64,
    require_positive: bool,
) -> Result<(), Failure> {
    if let Some(value) = object.get(name) {
        let number = value
            .as_u64()
            .ok_or_else(|| invalid(&format!("{name} must be a non-negative integer")))?;
        if number > maximum || (require_positive && number == 0) {
            return Err(invalid(&format!("{name} is outside the supported bound")));
        }
    }
    Ok(())
}
fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        true,
        "Correct the input and retry.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}
