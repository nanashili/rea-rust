//! `traceNativeValues` (`application/native/NativeValueTrace.ts`).
//!
//! Composes bounded high-p-code def-use graphs across exactly referenced call
//! destinations, preserving decompiler-derived dependencies, call bindings and
//! every provider-supplied limitation and unknown.
use super::schema::{native_call_targets, native_value_trace};
use crate::analysis::{Analysis, is_cancellation, params};
use crate::domain::dossier::parse_function_dossier;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, Observation};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

/// 8 MiB node payload budget (`NODE_PAYLOAD_BYTES`).
const NODE_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
/// 32 MiB complete serialized output bound.
const OUTPUT_BYTES: usize = 32 * 1024 * 1024;

const OPERATION: &str = "trace_native_values";

/// One queued procedure selector and its traversal depth.
struct Pending {
    procedure: String,
    depth: i64,
}

/// A retained call binding (`callBindings` element).
struct CallBinding {
    caller: String,
    callee: String,
    call: String,
    argument_count: i64,
    output: bool,
    evidence_id: String,
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// `traceNativeValues` over the validated tool input.
pub fn trace_native_values(analysis: &Analysis<'_>, input: &Value) -> Result<Value, AnalysisError> {
    // Input has already been validated against `nativeValueTraceInputSchema`
    // with declared defaults applied.
    let procedure = string_field(input, "procedure");
    let max_depth = input["max_depth"].as_i64().unwrap_or(3);
    let max_functions = input["max_functions"].as_i64().unwrap_or(16);
    let max_call_sites = input["max_call_sites"].as_i64().unwrap_or(256);
    let max_nodes = input["max_nodes"].as_i64().unwrap_or(5_000);
    let max_edges = input["max_edges"].as_i64().unwrap_or(10_000);
    let offset = input["offset"].as_u64().unwrap_or(0) as usize;
    let limit = input["limit"].as_u64().unwrap_or(1_000) as usize;

    let mut nodes: Vec<Value> = Vec::new();
    let mut edges: Vec<Value> = Vec::new();
    let mut procedures: Vec<Value> = Vec::new();
    let mut unknowns: Vec<Value> = Vec::new();
    let mut source_limitations: Vec<SourceLimitation> = Vec::new();
    let mut call_bindings: Vec<CallBinding> = Vec::new();

    let mut pending: Vec<Pending> = vec![Pending {
        procedure: procedure.clone(),
        depth: 0,
    }];
    let mut attempted: HashSet<String> = HashSet::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut target_sha256: Option<String> = None;
    let mut truncated = false;
    let mut decompilations: i64 = 0;
    let mut call_sites: i64 = 0;
    let mut bytes: usize = 0;
    let mut node_budget_reached = false;

    let mut head = 0usize;
    while head < pending.len() {
        if analysis.aborted() {
            return Err(AnalysisError::cancelled(OPERATION));
        }
        let next = pending[head].procedure.clone();
        let next_depth = pending[head].depth;
        head += 1;
        if attempted.contains(&next) || visited.contains(&next) {
            continue;
        }
        if decompilations >= max_functions {
            truncated = true;
            unknowns.push(json!({
                "procedure": next,
                "address": Value::Null,
                "reason": "decompilation budget reached",
            }));
            break;
        }
        // An exact selector is attempted once per trace, even on failure.
        attempted.insert(next.clone());
        let selector_from_provider = next_depth > 0;
        let execution = match analysis.execute(
            "analyze_function",
            &params([("procedure", json!(next))]),
            selector_from_provider,
        ) {
            Ok(execution) => execution,
            Err(error) => {
                decompilations += 1;
                if is_cancellation(&error) {
                    return Err(error);
                }
                unknowns.push(json!({
                    "procedure": next,
                    "address": Value::Null,
                    "reason": error.message(),
                }));
                continue;
            }
        };
        decompilations += 1;
        let dossier = match parse_function_dossier(&execution.result) {
            Ok(dossier) if execution.subject.is_some() => dossier,
            _ => {
                return Err(AnalysisError::output(
                    OPERATION,
                    "Function dossier lacks validated facts or artifact identity",
                ));
            }
        };
        let address = string_field(&dossier["procedure"], "address");
        if visited.contains(&address) {
            continue;
        }
        visited.insert(next.clone());
        visited.insert(address.clone());
        let subject = execution.subject.as_ref().expect("subject checked above");
        if target_sha256.is_none() {
            target_sha256 = Some(subject.sha256.clone());
        }
        if subject.sha256 != *target_sha256.as_ref().expect("set above") {
            return Err(AnalysisError::output(
                OPERATION,
                "Cross-function target digest mismatch",
            ));
        }

        // createEvidence(subject, provider, {...}) — confidence defaults to
        // "observed"; relationship_coverage is not supplied.
        let mut observation = Observation::new(
            "analyze_function",
            json!({ "procedure": next }),
            execution.result.clone(),
        )
        .confidence("observed")
        .limitations(execution.limitations.clone())
        .locations(execution.locations.clone());
        if let Some(raw) = &execution.raw_result {
            observation = observation.raw(raw.clone());
        }
        if let Some(profile) = &execution.analysis_profile {
            observation = observation.profile(profile.clone());
        }
        let evidence = Evidence::create(
            execution.subject.as_ref(),
            &execution.provider.evidence_provider(),
            observation,
        )
        .map_err(|error| AnalysisError::output("analyze_function", error.to_string()))?;
        let evidence_id = evidence.id().to_owned();

        procedures.push(json!({
            "address": address,
            "depth": next_depth,
            "evidence_id": evidence_id,
            "provider": execution.provider.id,
            "analysis_profile_digest": execution
                .analysis_profile
                .as_ref()
                .and_then(|profile| profile.get("digest"))
                .cloned()
                .unwrap_or(Value::Null),
        }));

        let flow = &dossier["native_value_flow"];
        let flow_available = flow
            .get("available")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if flow.is_null() || !flow_available {
            let reason = flow
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| "Provider has no native def-use model".to_owned());
            unknowns.push(json!({
                "procedure": address,
                "address": Value::Null,
                "reason": reason,
            }));
            continue;
        }
        if flow
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            truncated = true;
            unknowns.push(json!({
                "procedure": address,
                "address": Value::Null,
                "reason": "Provider p-code was truncated",
            }));
        }

        let empty: Vec<Value> = Vec::new();
        let operations = flow["operations"].as_array().unwrap_or(&empty);
        let parameters_list = flow["parameters"].as_array().unwrap_or(&empty);
        let parameter_uses = flow["parameter_uses"].as_array().unwrap_or(&empty);
        let def_use = flow["def_use"].as_array().unwrap_or(&empty);

        let mut ids: HashSet<String> = HashSet::new();
        // Preserve every provider-supplied operation ID for parameter naming.
        let operation_ids: HashSet<String> =
            operations.iter().map(|op| string_field(op, "id")).collect();
        let mut parameter_ids: HashMap<i64, String> = HashMap::new();
        let qualified = |id: &str| format!("{address}/{id}");

        for operation in operations {
            let block = operation
                .get("block_membership")
                .and_then(Value::as_str)
                .unwrap_or("");
            let is_dead = operation
                .get("is_dead")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if block == "detached" || (block == "unavailable" && is_dead) {
                continue;
            }
            let op_id = string_field(operation, "id");
            let node = json!({
                "id": qualified(&op_id),
                "procedure": address,
                "evidence_id": evidence_id,
                "operation": operation,
                "kind": "operation",
                "parameter": Value::Null,
            });
            if !retain_node(
                node,
                &mut nodes,
                &mut bytes,
                max_nodes,
                &mut truncated,
                &mut node_budget_reached,
            ) {
                break;
            }
            ids.insert(op_id);
        }

        for parameter in parameters_list {
            let ordinal = parameter
                .get("ordinal")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let parameter_id = format!("parameter:{ordinal}");
            let mut local_id = parameter_id.clone();
            let mut suffix = 1u64;
            while operation_ids.contains(&local_id) {
                local_id = format!("{parameter_id}#{suffix}");
                suffix += 1;
            }
            let id = qualified(&local_id);
            let node = json!({
                "id": id,
                "procedure": address,
                "evidence_id": evidence_id,
                "kind": "parameter",
                "operation": Value::Null,
                "parameter": parameter,
            });
            if !retain_node(
                node,
                &mut nodes,
                &mut bytes,
                max_nodes,
                &mut truncated,
                &mut node_budget_reached,
            ) {
                break;
            }
            parameter_ids.insert(ordinal, id);
        }

        for use_entry in parameter_uses {
            let ordinal = use_entry
                .get("ordinal")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let use_id = string_field(use_entry, "use");
            let Some(source) = parameter_ids.get(&ordinal) else {
                continue;
            };
            if !ids.contains(&use_id) {
                continue;
            }
            if edges.len() as i64 >= max_edges {
                truncated = true;
                break;
            }
            edges.push(json!({
                "source": source,
                "target": qualified(&use_id),
                "input_index": use_entry.get("input_index").cloned().unwrap_or(Value::Null),
                "kind": "parameter-use",
                "status": "derived",
                "evidence_id": evidence_id,
            }));
        }

        for edge in def_use {
            let definition = string_field(edge, "definition");
            let use_id = string_field(edge, "use");
            if !ids.contains(&definition) || !ids.contains(&use_id) {
                continue;
            }
            if edges.len() as i64 >= max_edges {
                truncated = true;
                break;
            }
            edges.push(json!({
                "source": qualified(&definition),
                "target": qualified(&use_id),
                "input_index": edge.get("input_index").cloned().unwrap_or(Value::Null),
                "kind": "def-use",
                "status": "derived",
                "evidence_id": evidence_id,
            }));
        }

        for operation in operations {
            let op_id = string_field(operation, "id");
            let opcode = operation
                .get("opcode")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !ids.contains(&op_id) || !(opcode == "CALL" || opcode == "CALLIND") {
                continue;
            }
            let op_address = string_field(operation, "address");
            if call_sites >= max_call_sites {
                truncated = true;
                unknowns.push(json!({
                    "procedure": address,
                    "address": op_address,
                    "reason": "Call-site resolution budget reached",
                }));
                break;
            }
            call_sites += 1;
            let resolved = match analysis.execute(
                "resolve_native_call_targets",
                &params([("address", json!(op_address))]),
                false,
            ) {
                Ok(resolved) => resolved,
                Err(error) => {
                    if is_cancellation(&error) {
                        return Err(error);
                    }
                    unknowns.push(json!({
                        "procedure": address,
                        "address": op_address,
                        "reason": error.message(),
                    }));
                    continue;
                }
            };
            let targets = native_call_targets().parse(&resolved.result).map_err(|_| {
                AnalysisError::output(
                    "resolve_native_call_targets",
                    "Invalid static call resolution",
                )
            })?;
            if let Some(limitations) = targets["limitations"].as_array() {
                for limitation in limitations {
                    if let Some(limitation) = limitation.as_str() {
                        source_limitations.push(SourceLimitation {
                            provider_id: resolved.provider.id.clone(),
                            provider_name: resolved.provider.name.clone(),
                            provider_version: resolved.provider.version.clone(),
                            operation: "resolve_native_call_targets".to_owned(),
                            limitation: limitation.to_owned(),
                        });
                    }
                }
            }
            let target_list = targets["targets"].as_array().cloned().unwrap_or_default();
            if target_list.is_empty() {
                let status = targets.get("status").and_then(Value::as_str).unwrap_or("");
                unknowns.push(json!({
                    "procedure": address,
                    "address": op_address,
                    "reason": format!("Call target {status}"),
                }));
            }
            for target in &target_list {
                if edges.len() as i64 >= max_edges {
                    truncated = true;
                    break;
                }
                let target_status = target.get("status").and_then(Value::as_str).unwrap_or("");
                let destination = match target.get("procedure").and_then(Value::as_str) {
                    Some(proc) => proc.to_owned(),
                    None => string_field(target, "address"),
                };
                edges.push(json!({
                    "source": qualified(&op_id),
                    "target": destination,
                    "input_index": Value::Null,
                    "kind": "call",
                    "status": target_status,
                    "evidence_id": evidence_id,
                }));
                if target_status != "candidate" {
                    let inputs_len = operation
                        .get("inputs")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                        .unwrap_or(0) as i64;
                    call_bindings.push(CallBinding {
                        caller: address.clone(),
                        callee: destination.clone(),
                        call: qualified(&op_id),
                        argument_count: (inputs_len - 1).max(0),
                        output: !operation.get("output").map(Value::is_null).unwrap_or(true),
                        evidence_id: evidence_id.clone(),
                    });
                }
                if next_depth < max_depth && target_status != "candidate" {
                    pending.push(Pending {
                        procedure: destination.clone(),
                        depth: next_depth + 1,
                    });
                } else if !visited.contains(&destination) {
                    truncated = true;
                    unknowns.push(json!({
                        "procedure": address,
                        "address": op_address,
                        "reason": if target_status == "candidate" {
                            "Ambiguous call candidates were not traversed"
                        } else {
                            "Call depth budget reached"
                        },
                    }));
                }
            }
        }

        if truncated
            && (node_budget_reached
                || nodes.len() as i64 >= max_nodes
                || edges.len() as i64 >= max_edges
                || bytes >= NODE_PAYLOAD_BYTES)
        {
            break;
        }
    }

    let Some(target_sha256) = target_sha256 else {
        return Err(AnalysisError::output(
            OPERATION,
            "No seed function could be analyzed",
        ));
    };

    // Index parameters and multi-input RETURN nodes by procedure.
    let mut parameters_by_procedure: HashMap<String, Vec<usize>> = HashMap::new();
    let mut returns_by_procedure: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, node) in nodes.iter().enumerate() {
        let node_procedure = string_field(node, "procedure");
        if node.get("kind").and_then(Value::as_str) == Some("parameter") {
            parameters_by_procedure
                .entry(node_procedure)
                .or_default()
                .push(index);
        } else {
            let operation = &node["operation"];
            let opcode = operation.get("opcode").and_then(Value::as_str);
            let inputs_len = operation
                .get("inputs")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            if opcode == Some("RETURN") && inputs_len > 1 {
                returns_by_procedure
                    .entry(node_procedure)
                    .or_default()
                    .push(index);
            }
        }
    }

    for binding in &call_bindings {
        let parameter_indices = parameters_by_procedure
            .get(&binding.callee)
            .cloned()
            .unwrap_or_default();
        if parameter_indices.is_empty() {
            unknowns.push(json!({
                "procedure": binding.caller,
                "address": Value::Null,
                "reason": format!("Parameter bindings for {} are unavailable or omitted", binding.callee),
            }));
        }
        for &index in &parameter_indices {
            let node = &nodes[index];
            let ordinal = node["parameter"].get("ordinal").and_then(Value::as_i64);
            match ordinal {
                Some(ordinal) if ordinal < binding.argument_count => {
                    if edges.len() as i64 >= max_edges {
                        truncated = true;
                        break;
                    }
                    edges.push(json!({
                        "source": binding.call,
                        "target": string_field(node, "id"),
                        "input_index": ordinal + 1,
                        "kind": "argument-binding",
                        "status": "derived",
                        "evidence_id": binding.evidence_id,
                    }));
                }
                _ => {
                    let ordinal_label = ordinal
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "unknown".to_owned());
                    unknowns.push(json!({
                        "procedure": binding.caller,
                        "address": Value::Null,
                        "reason": format!("Argument {} for {} was not recovered", ordinal_label, binding.callee),
                    }));
                }
            }
        }
        if binding.output {
            for &index in returns_by_procedure
                .get(&binding.callee)
                .map(Vec::as_slice)
                .unwrap_or(&[])
            {
                if edges.len() as i64 >= max_edges {
                    truncated = true;
                    break;
                }
                let node = &nodes[index];
                edges.push(json!({
                    "source": string_field(node, "id"),
                    "target": binding.call,
                    "input_index": 1,
                    "kind": "return-binding",
                    "status": "derived",
                    "evidence_id": string_field(node, "evidence_id"),
                }));
            }
        }
    }

    let total_nodes = nodes.len();
    let total_edges = edges.len();
    let page_end = (offset + limit).min(nodes.len());
    let page: Vec<Value> = if offset >= nodes.len() {
        Vec::new()
    } else {
        nodes[offset..page_end].to_vec()
    };
    let page_len = page.len();
    let page_ids: HashSet<String> = page.iter().map(|node| string_field(node, "id")).collect();
    let page_edges: Vec<Value> = edges
        .into_iter()
        .filter(|edge| page_ids.contains(&string_field(edge, "source")))
        .collect();

    let next_offset = if offset + page_len < total_nodes {
        json!(offset + page_len)
    } else {
        Value::Null
    };
    let result_truncated = truncated || page_len != total_nodes;

    let mut limitations = vec![
        "Static decompiler def-use graphs cover recovered block members; when membership is unavailable they exclude operations marked dead. Logical CALL argument positions bind to recovered HighParam ordinals and RETURN values bind to recovered CALL outputs; these are decompiler-derived dependencies, not original source or runtime observations. Missing parameters, variadic arguments and alias dependencies remain unknown.".to_owned(),
        "LOAD and STORE are memory operations; object fields, persistent state and RNG semantics are not inferred from names or pseudocode.".to_owned(),
        "Traversal caps depth, decompilations, call-site resolutions, nodes, edges and node payloads (8 MiB). Complete serialized output is bounded to 32 MiB. Pagination reruns analysis and returns edges whose source is on the node page; endpoints outside the page retain stable identities.".to_owned(),
    ];
    limitations.extend(render_source_limitations(&source_limitations));

    let unparsed = json!({
        "seed": procedure,
        "target_sha256": target_sha256,
        "nodes": page,
        "edges": page_edges,
        "procedures": procedures,
        "unknowns": unknowns,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "decompilations": decompilations,
        "next_offset": next_offset,
        "truncated": result_truncated,
        "limitations": limitations,
    });

    let result = native_value_trace().parse(&unparsed).map_err(|issue| {
        AnalysisError::output(
            OPERATION,
            format!("value trace output does not satisfy its contract: {issue}"),
        )
    })?;

    if serde_json::to_string(&result)
        .map(|text| text.len())
        .unwrap_or(usize::MAX)
        > OUTPUT_BYTES
    {
        return Err(AnalysisError::output(
            OPERATION,
            "Graph output exceeds 32 MiB; lower max_nodes, max_edges or page limit",
        ));
    }
    Ok(result)
}

/// `retainNode`: honor the node count and 8 MiB payload budgets while counting
/// escapes and UTF-8 expansion of the serialized node.
fn retain_node(
    value: Value,
    nodes: &mut Vec<Value>,
    bytes: &mut usize,
    max_nodes: i64,
    truncated: &mut bool,
    node_budget_reached: &mut bool,
) -> bool {
    if *node_budget_reached {
        return false;
    }
    if nodes.len() as i64 >= max_nodes {
        *truncated = true;
        *node_budget_reached = true;
        return false;
    }
    // `jsonParts(value)` summed as UTF-8 byte length equals the byte length of
    // the serialized node; the running check rejects once the remaining payload
    // budget would be exceeded.
    let size = serde_json::to_string(&value)
        .map(|text| text.len())
        .unwrap_or(usize::MAX);
    if size > NODE_PAYLOAD_BYTES.saturating_sub(*bytes) {
        *truncated = true;
        *node_budget_reached = true;
        return false;
    }
    *bytes += size;
    nodes.push(value);
    true
}

/// One provider-owned caveat tied to the operation that reported it
/// (`SourceLimitation`).
struct SourceLimitation {
    provider_id: String,
    provider_name: String,
    provider_version: Option<String>,
    operation: String,
    limitation: String,
}

/// `renderSourceLimitations`.
fn render_source_limitations(limitations: &[SourceLimitation]) -> Vec<String> {
    struct Group {
        provider_id: String,
        provider_name: String,
        provider_version: Option<String>,
        limitation: String,
        operations: Vec<String>,
    }
    let mut groups: Vec<(String, Group)> = Vec::new();
    for fact in limitations {
        let key = serde_json::to_string(&json!([
            fact.provider_id,
            fact.provider_name,
            fact.provider_version,
            fact.limitation,
        ]))
        .unwrap_or_default();
        match groups.iter_mut().find(|(existing, _)| *existing == key) {
            Some((_, group)) => {
                if !group.operations.contains(&fact.operation) {
                    group.operations.push(fact.operation.clone());
                }
            }
            None => groups.push((
                key,
                Group {
                    provider_id: fact.provider_id.clone(),
                    provider_name: fact.provider_name.clone(),
                    provider_version: fact.provider_version.clone(),
                    limitation: fact.limitation.clone(),
                    operations: vec![fact.operation.clone()],
                },
            )),
        }
    }
    let mut rendered = groups
        .into_iter()
        .map(|(_, group)| {
            let version = group
                .provider_version
                .as_ref()
                .map_or_else(String::new, |version| format!(" {version}"));
            let mut operations = group.operations;
            operations.sort_by(|left, right| crate::js::compare_code_points(left, right));
            format!(
                "{} ({}{}) {}: {}",
                group.provider_name,
                group.provider_id,
                version,
                operations.join(", "),
                group.limitation
            )
        })
        .collect::<Vec<_>>();
    rendered.sort_by(|left, right| crate::js::compare_code_points(left, right));
    rendered
}
