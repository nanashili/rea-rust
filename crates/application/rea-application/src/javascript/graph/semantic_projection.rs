//! Per-file semantic projection passes (`JavaScriptSemanticGraph*Projection`).

use std::collections::HashMap;

use super::super::semantic::value_types::JsString;
use super::evidence::partial_coverage;
use super::json::{Json, Obj, js_int, strings, utf16_len};
use super::leaves::{
    SlotFact, container, property_pointer_js, semantic_resource_limit_coverage,
    semantic_resource_limit_reason, slot_at_value,
};
use super::semantic_graph::{
    NodeSpec, ProjectionState, RelationSpec, UnknownSpec, add_relation, add_unknown,
    inferred_evidence_at, retain_node, unknown_evidence,
};
use super::semantic_ir_view::{BindingValueLookup, SemanticCollection, SemanticIrView};
use super::semantic_lookup::{CallableOwnerLookup, NodeRangeLookup, range_key};

/// File-local projection context.
pub struct FileContext<'s> {
    /// Source file.
    pub file: Json,
    /// Semantic IR.
    pub ir: SemanticIrView,
    /// Projection state.
    pub state: &'s mut ProjectionState,
    /// Module node.
    pub module_node: Json,
    /// Binding nodes by binding id.
    pub binding_nodes: HashMap<String, Json>,
    /// Callable nodes by callable id.
    pub callable_nodes: HashMap<String, Json>,
    /// Call-site nodes by call-site id.
    pub call_site_nodes: HashMap<String, Json>,
    /// Return-site nodes by return-site id.
    pub return_site_nodes: HashMap<String, Json>,
    /// Argument nodes by call-site and index.
    pub argument_nodes: HashMap<String, Json>,
    /// Call resolutions by call-site id.
    pub call_resolutions: HashMap<String, &'static str>,
    /// Callable owner lookup.
    pub owners: CallableOwnerLookup,
    /// First call-site id by exact range.
    pub call_sites_by_range: HashMap<String, String>,
    /// Reference range lookup.
    pub references: Option<NodeRangeLookup>,
}

impl FileContext<'_> {
    fn call_site_at(&self, location: &Json) -> Option<Json> {
        self.call_sites_by_range
            .get(&range_key(location))
            .and_then(|id| self.call_site_nodes.get(id))
            .cloned()
    }

    fn references_within(&self, location: &Json) -> Vec<Json> {
        self.references
            .as_ref()
            .map(|lookup| lookup.within(location).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    fn callable_node_id(&self, callable: &Json) -> Option<String> {
        callable
            .as_str()
            .and_then(|id| self.callable_nodes.get(id))
            .map(|node| node.at("node_id").str().to_owned())
    }

    fn binding(&self, id: &Json) -> Option<Json> {
        id.as_str()
            .and_then(|id| self.binding_nodes.get(id))
            .cloned()
    }

    fn callable(&self, id: &Json) -> Option<Json> {
        id.as_str()
            .and_then(|id| self.callable_nodes.get(id))
            .cloned()
    }

    fn retain(&mut self, spec: NodeSpec<'_>) -> Option<Json> {
        retain_node(self.state, &self.file, spec)
    }

    fn observed_evidence(&mut self, location: &Json) -> Json {
        self.state.observed_evidence(&self.file, location)
    }

    fn inferred_evidence(&mut self, location: &Json) -> Json {
        self.state.inferred_evidence(&self.file, location)
    }

    fn unknown_evidence(&mut self, location: &Json) -> Json {
        self.state.unknown_evidence(&self.file, location)
    }

    fn relate(
        &mut self,
        source: Option<&Json>,
        target: Option<&Json>,
        relation: &str,
        resolution: &str,
    ) {
        add_relation(
            self.state,
            RelationSpec::new(source, target, relation, resolution),
        );
    }

    fn unknown(&mut self, spec: UnknownSpec<'_>) {
        add_unknown(self.state, spec);
    }
}

fn resolution(complete: bool) -> &'static str {
    if complete { "resolved" } else { "candidate" }
}

fn is_complete(value: &Json) -> bool {
    value.str() == "complete"
}

fn node_id(node: Option<&Json>) -> Option<String> {
    node.map(|node| node.at("node_id").str().to_owned())
}

fn to_strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn js_string_path(value: &Json) -> Vec<JsString> {
    value.arr().iter().map(|item| item.text().clone()).collect()
}

fn owner_id(context: &FileContext<'_>, owner: &Json) -> Option<String> {
    context.callable_node_id(owner)
}

// ---------------------------------------------------------------- values

/// `projectSemanticValues`.
pub fn project_values(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    let retained_bindings =
        ir.binding_indices_matching(|id| context.binding_nodes.contains_key(id));
    for index in retained_bindings {
        let Some(binding) = ir.binding_header_at(index) else {
            continue;
        };
        let binding_id = binding.at("bindingId");
        let Some(node) = context.binding(binding_id) else {
            continue;
        };
        let Some(value) = ir.binding_value_at(index) else {
            continue;
        };
        project_value(context, &binding, &value, Some(node), &[]);
    }
}

fn project_value(
    context: &mut FileContext<'_>,
    binding: &Json,
    value: &Json,
    target: Option<Json>,
    path: &[JsString],
) {
    let role = if path.is_empty() {
        JsString::from("binding")
    } else {
        JsString::from("property:").concat(&property_pointer_js(path))
    };
    let Some(target) = target else { return };
    let location = binding
        .at("definitions")
        .arr()
        .first()
        .map_or(Json::Null, |definition| definition.at("location").clone());
    match value.at("status").str() {
        "literal" => {
            let literal = literal_node(context, binding, value.at("value"), &role);
            context.relate(literal.as_ref(), Some(&target), "defines", "resolved");
        }
        "union" => {
            for primitive in value.at("values").arr() {
                let literal = literal_node(context, binding, primitive, &role);
                context.relate(literal.as_ref(), Some(&target), "defines", "candidate");
            }
        }
        "object" | "array" => {
            let Some(inventory) = container(value) else {
                return;
            };
            let slots = inventory.slots.to_vec();
            for property in &slots {
                let mut property_path = path.to_vec();
                property_path.push(property.at("name").text().clone());
                let slot = property_slot(
                    context,
                    binding.at("bindingId").str(),
                    &property_path,
                    &SlotFact::Observed(property),
                );
                let presence = property.at("presence").str();
                if presence == "absent" {
                    continue;
                }
                context.relate(
                    Some(&target),
                    slot.as_ref(),
                    "writes-property",
                    resolution(presence == "present"),
                );
                if presence == "present" {
                    project_value(context, binding, property.at("value"), slot, &property_path);
                }
            }
            if inventory.coverage.at("status").str() == "partial" {
                let omitted = inventory.coverage.at("omitted");
                let detail = format!(
                    "Initializer container has unknown {}{}.",
                    if value.at("status").str() == "object" {
                        "properties"
                    } else {
                        "items"
                    },
                    if omitted.is_null() {
                        " with an unknown omitted count".to_owned()
                    } else {
                        format!("; {} omitted", js_int(omitted.num()))
                    }
                );
                let evidence = context.unknown_evidence(&location);
                let id = target.at("node_id").str().to_owned();
                context.unknown(UnknownSpec {
                    node_id: Some(id.clone()),
                    family: "object-flow",
                    relation_kinds: to_strings(&["writes-property"]),
                    reason: "ambiguous-target",
                    detail: detail.into(),
                    candidate_node_ids: vec![id],
                    evidence,
                });
            }
        }
        "unknown" | "ambiguous" | "cycle" => {
            let mut evidence = context.observed_evidence(&location).obj();
            evidence.set("authority", "unknown");
            evidence.set("state", "unknown");
            evidence.set("confidence", "unknown");
            evidence.set("limitations", Json::array(vec![value.at("reason").clone()]));
            let id = target.at("node_id").str().to_owned();
            context.unknown(UnknownSpec {
                node_id: Some(id.clone()),
                family: "data-flow",
                relation_kinds: to_strings(&["defines"]),
                reason: if value.get("resourceLimit").is_none() {
                    "unknown-value"
                } else {
                    "resource-limit"
                },
                detail: JsString::from(value.at("reason").str())
                    .concat_str(" Unknown value at ")
                    .concat(&role)
                    .concat_str("."),
                candidate_node_ids: vec![id],
                evidence: evidence.into(),
            });
        }
        _ => {}
    }
}

fn literal_node(
    context: &mut FileContext<'_>,
    binding: &Json,
    value: &Json,
    role: &JsString,
) -> Option<Json> {
    let encoded = value.stringify();
    let digest = format!("value-sha256:{}", value.digest());
    let key = if utf16_len(&encoded) <= utf16_len(&digest) {
        encoded.clone()
    } else {
        digest
    };
    let label = if value.as_str().is_some() && utf16_len(&encoded) > utf16_len("string literal") {
        "string literal".to_owned()
    } else {
        encoded
    };
    let binding_id = binding.at("bindingId").str();
    let function = context
        .binding_nodes
        .get(binding_id)
        .and_then(|node| node.at("function_node_id").as_js_string())
        .cloned();
    let location = binding
        .at("definitions")
        .arr()
        .first()
        .map_or(Json::Null, |definition| definition.at("location").clone());
    context.retain(NodeSpec {
        kind: "literal",
        role_key: JsString::from(format!("literal:{binding_id}:"))
            .concat(role)
            .concat_str(":")
            .concat_str(&key),
        location,
        label: Some(label.into()),
        function_node_id: function.map(Into::into),
        properties: Obj::new().with_static("value", value.clone()),
    })
}

/// `semanticPropertySlot`.
fn property_slot(
    context: &mut FileContext<'_>,
    binding_id: &str,
    path: &[JsString],
    fact: &SlotFact<'_>,
) -> Option<Json> {
    let function = context
        .binding_nodes
        .get(binding_id)
        .and_then(|node| node.at("function_node_id").as_str())
        .map(str::to_owned);
    let role_key = format!(
        "property:{}",
        Json::array(vec![
            binding_id.into(),
            Json::array(path.iter().cloned().map(Json::from).collect()),
        ])
        .stringify()
    );
    context.retain(NodeSpec {
        kind: "property-slot",
        role_key: role_key.into(),
        location: Json::Null,
        label: Some(fact.name()),
        function_node_id: function.map(Into::into),
        properties: Obj::new()
            .with_static("name", fact.raw_name())
            .with_static(
                "property_path",
                Json::array(path.iter().cloned().map(Json::from).collect()),
            )
            .with_static("property_pointer", property_pointer_js(path))
            .with_static("object_binding_id", binding_id)
            .with_static("presence", fact.raw_presence())
            .with_static("value_status", fact.value_status())
            .with_static("value_coverage", fact.value_coverage()),
    })
}

// ---------------------------------------------------------------- objects

/// `projectSemanticObjects`.
pub fn project_objects(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    let values = ir.binding_values();
    for operation in ir.records(SemanticCollection::ObjectOperations) {
        let kind = operation.at("kind").str();
        let path = operation.at("propertyPath");
        let label = if path.is_null() {
            JsString::from(kind)
        } else {
            JsString::from(kind)
                .concat_str(":")
                .concat(&property_pointer_js(&js_string_path(path)))
        };
        let function = owner_id(context, operation.at("ownerCallableId"));
        let occurrence = context.retain(NodeSpec {
            kind: "expression",
            role_key: operation.at("objectOperationId").str().to_owned().into(),
            location: operation.at("location").clone(),
            label: Some(label),
            function_node_id: function.map(Into::into),
            properties: Obj::new().with_static("operation_kind", kind).with_static(
                "property_path",
                if path.is_null() {
                    Json::Null
                } else {
                    path.clone()
                },
            ),
        });
        let (object_node, slot, presence, receiver_resolved) =
            object_target(context, &values, &operation);
        let (source, target) = match kind {
            "read" => (slot.clone(), occurrence.clone()),
            "write" => (occurrence.clone(), slot.clone()),
            "destructure" => (
                slot.clone(),
                context.binding(operation.at("targetBindingId")),
            ),
            _ => (object_node.clone(), occurrence.clone()),
        };
        let resolved = operation.at("resolution").str() == "complete"
            && if kind == "write" {
                receiver_resolved
            } else {
                presence == "present"
            };
        let relation = object_relation(kind);
        context.relate(
            source.as_ref(),
            target.as_ref(),
            relation,
            resolution(resolved),
        );
        if !resolved {
            let node = slot.or(occurrence);
            let path_text = if path.is_null() {
                JsString::from("path is unresolved")
            } else {
                property_pointer_js(&js_string_path(path))
            };
            let detail = JsString::from("Static ")
                .concat_str(kind)
                .concat_str(" property ")
                .concat(&path_text)
                .concat_str(" has ")
                .concat_str(&presence)
                .concat_str(" presence; its receiver is ")
                .concat_str(if receiver_resolved {
                    "a retained container"
                } else {
                    "unresolved or not a retained container"
                })
                .concat_str("; object identity is ")
                .concat_str(operation.at("resolution").str())
                .concat_str(".");
            let evidence = context.unknown_evidence(operation.at("location"));
            context.unknown(UnknownSpec {
                node_id: node_id(node.as_ref()),
                family: "object-flow",
                relation_kinds: vec![relation.to_owned()],
                reason: "ambiguous-target",
                detail,
                candidate_node_ids: Vec::new(),
                evidence,
            });
        }
    }
}

fn object_relation(kind: &str) -> &'static str {
    match kind {
        "read" => "reads-property",
        "write" => "writes-property",
        "destructure" => "destructures",
        _ => "spreads",
    }
}

fn object_target(
    context: &mut FileContext<'_>,
    values: &BindingValueLookup<'_>,
    operation: &Json,
) -> (Option<Json>, Option<Json>, String, bool) {
    let object_id = operation.at("objectBindingId");
    let binding = context.binding(object_id);
    let path = operation.at("propertyPath");
    let (Some(object_id), false) = (object_id.as_str(), path.is_null()) else {
        return (binding, None, "unknown-coverage".to_owned(), false);
    };
    let path = js_string_path(path);
    let Some(value) = values.value(object_id) else {
        return (binding, None, "unknown-coverage".to_owned(), false);
    };
    let fact = slot_at_value(value, &path);
    let presence = fact.presence().to_owned();
    if path.is_empty() {
        return (binding, None, presence, fact.is_container());
    }
    let slot = property_slot(context, object_id, &path, &fact);
    let receiver = slot_at_value(value, &path[..path.len().saturating_sub(1)]);
    let receiver_resolved = receiver.presence() == "present" && receiver.is_container();
    (slot.clone(), slot, presence, receiver_resolved)
}

// ---------------------------------------------------------------- calls

/// `projectCalls`.
pub fn project_calls(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    for call in ir.records(SemanticCollection::CallSites) {
        let call_id = call.at("callSiteId").str();
        let Some(call_node) = context.call_site_nodes.get(call_id).cloned() else {
            continue;
        };
        for callable in call.at("calleeCallableIds").arr() {
            let target = context.callable(callable);
            context.relate(
                Some(&call_node),
                target.as_ref(),
                "calls",
                resolution(call.at("resolution").str() == "exact"),
            );
        }
        for argument in call.at("arguments").arr() {
            let index = js_int(argument.at("index").num());
            let label = if argument.at("spread").as_bool() == Some(true) {
                "spread argument".to_owned()
            } else {
                format!("argument {index}")
            };
            let argument_node = context.retain(NodeSpec {
                kind: "expression",
                role_key: format!("argument:{call_id}:{index}").into(),
                location: argument.at("location").clone(),
                label: Some(label.into()),
                function_node_id: call_node.at("function_node_id").as_js_string().cloned(),
                properties: Obj::new(),
            });
            if let Some(node) = &argument_node {
                context
                    .argument_nodes
                    .insert(format!("{call_id}\0{index}"), node.clone());
            }
            let references = context.references_within(argument.at("location"));
            let single = references.len() == 1;
            for reference in &references {
                let exact = single
                    && reference.at("identity").at("source_range") == argument.at("location");
                context.relate(
                    Some(reference),
                    argument_node.as_ref(),
                    "aliases",
                    resolution(exact),
                );
            }
        }
    }
    let ir = context.ir.clone();
    for flow in ir.records(SemanticCollection::ArgumentFlows) {
        let argument = context
            .argument_nodes
            .get(&format!(
                "{}\0{}",
                flow.at("callSiteId").str(),
                js_int(flow.at("argumentIndex").num())
            ))
            .cloned();
        let parameter = context.binding(flow.at("parameterBindingId"));
        let resolution = context
            .call_resolutions
            .get(flow.at("callSiteId").str())
            .copied()
            .unwrap_or("candidate");
        context.relate(
            argument.as_ref(),
            parameter.as_ref(),
            "argument-to-parameter",
            resolution,
        );
    }
    let ir = context.ir.clone();
    for flow in ir.records(SemanticCollection::CallReturnFlows) {
        let source = context
            .return_site_nodes
            .get(flow.at("returnSiteId").str())
            .cloned();
        let target = context
            .call_site_nodes
            .get(flow.at("callSiteId").str())
            .cloned();
        let resolution = context
            .call_resolutions
            .get(flow.at("callSiteId").str())
            .copied()
            .unwrap_or("candidate");
        context.relate(
            source.as_ref(),
            target.as_ref(),
            "returns-to-call",
            resolution,
        );
    }
    let ir = context.ir.clone();
    for flow in ir.records(SemanticCollection::CallResultFlows) {
        let source = context
            .call_site_nodes
            .get(flow.at("callSiteId").str())
            .cloned();
        let target = context.binding(flow.at("bindingId"));
        let resolution = context
            .call_resolutions
            .get(flow.at("callSiteId").str())
            .copied()
            .unwrap_or("candidate");
        context.relate(source.as_ref(), target.as_ref(), "aliases", resolution);
    }
    project_return_values(context);
}

fn project_return_values(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    let retained_callables =
        ir.callable_indices_with_returns(|id| context.return_site_nodes.contains_key(id));
    for index in retained_callables {
        let Some(callable) = ir.callable_header_at(index) else {
            continue;
        };
        for site in callable.at("returnSites").arr() {
            let Some(return_node) = context
                .return_site_nodes
                .get(site.at("returnSiteId").str())
                .cloned()
            else {
                continue;
            };
            let identity = site.at("identityReferenceLocation");
            for reference in context.references_within(site.at("location")) {
                let exact =
                    !identity.is_null() && reference.at("identity").at("source_range") == identity;
                context.relate(
                    Some(&reference),
                    Some(&return_node),
                    "aliases",
                    resolution(exact),
                );
            }
        }
    }
}

// ---------------------------------------------------------------- promises

/// `projectSemanticPromises`.
pub fn project_promises(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    let mut nodes: HashMap<String, Json> = HashMap::new();
    for operation in ir.records(SemanticCollection::PromiseOperations) {
        let kind = operation.at("kind").str();
        let label = if kind == "awaited-expression" {
            "awaited expression".to_owned()
        } else {
            format!("Promise.{}", operation.at("method").str())
        };
        let function = owner_id(context, operation.at("ownerCallableId"));
        let node = context.retain(NodeSpec {
            kind: if kind == "awaited-expression" {
                "task"
            } else {
                "promise"
            },
            role_key: operation.at("promiseId").str().to_owned().into(),
            location: operation.at("location").clone(),
            label: Some(label.into()),
            function_node_id: function.map(Into::into),
            properties: Obj::new()
                .with_static("method", operation.at("method").clone())
                .with_static("operation_kind", kind)
                .with_static("ownership", operation.at("ownership").clone())
                .with_static(
                    "source_resolution",
                    operation.at("sourceResolution").clone(),
                ),
        });
        if let Some(node) = node {
            nodes.insert(operation.at("promiseId").str().to_owned(), node);
        }
    }
    for operation in ir.records(SemanticCollection::PromiseOperations) {
        let Some(promise) = nodes.get(operation.at("promiseId").str()).cloned() else {
            continue;
        };
        let kind = operation.at("kind").str();
        let complete = is_complete(operation.at("sourceResolution"));
        if kind != "awaited-expression" {
            let call = context.call_site_at(operation.at("location"));
            context.relate(
                call.as_ref(),
                Some(&promise),
                "creates-promise",
                resolution(kind != "chain" && complete),
            );
        }
        for source_id in operation.at("sourcePromiseIds").arr() {
            let source = nodes.get(source_id.str()).cloned();
            if kind == "aggregate" {
                context.relate(
                    Some(&promise),
                    source.as_ref(),
                    "aggregates",
                    resolution(complete),
                );
            } else {
                context.relate(
                    source.as_ref(),
                    Some(&promise),
                    "chains",
                    resolution(complete),
                );
            }
        }
        let owner = if operation.at("ownerCallableId").is_null() {
            Some(context.module_node.clone())
        } else {
            context.callable(operation.at("ownerCallableId"))
        };
        match operation.at("ownership").str() {
            "awaited" => context.relate(owner.as_ref(), Some(&promise), "awaits", "resolved"),
            "assigned" => {
                let binding = context.binding(operation.at("ownerBindingId"));
                context.relate(binding.as_ref(), Some(&promise), "owns", "resolved");
            }
            "returned" => {
                let site = operation
                    .at("returnSiteId")
                    .as_str()
                    .and_then(|id| context.return_site_nodes.get(id))
                    .cloned();
                context.relate(site.as_ref(), Some(&promise), "returns-task", "resolved");
            }
            "detached" => {
                context.relate(owner.as_ref(), Some(&promise), "detaches-task", "resolved")
            }
            _ => {}
        }
        if !complete && matches!(kind, "chain" | "aggregate" | "awaited-expression") {
            let candidates = operation
                .at("sourcePromiseIds")
                .arr()
                .iter()
                .filter_map(|id| node_id(nodes.get(id.str())))
                .collect();
            let evidence = context.unknown_evidence(operation.at("location"));
            context.unknown(UnknownSpec {
                node_id: node_id(Some(&promise)),
                family: "promise-ownership",
                relation_kinds: vec![
                    if kind == "aggregate" {
                        "aggregates"
                    } else {
                        "chains"
                    }
                    .to_owned(),
                ],
                reason: "ambiguous-target",
                detail: format!(
                    "Static {} source resolution was {}.",
                    operation.at("method").str(),
                    operation.at("sourceResolution").str()
                )
                .into(),
                candidate_node_ids: candidates,
                evidence,
            });
        }
    }
}

// ---------------------------------------------------------------- events and timers

/// `projectSemanticEvents`.
pub fn project_events(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    let mut events: HashMap<JsString, Json> = HashMap::new();
    for operation in ir.records(SemanticCollection::EventOperations) {
        let name = operation.at("eventName");
        let key = match name.as_js_string() {
            None => operation.at("eventId").text().clone(),
            Some(name) => operation
                .at("emitterKey")
                .text()
                .concat_str("\0")
                .concat(name),
        };
        let event = match events.get(&key).cloned() {
            Some(event) => Some(event),
            None => {
                let label = match name.as_js_string() {
                    Some(name) if name.len() > "event".encode_utf16().count() => {
                        Some(JsString::from("event"))
                    }
                    Some(name) => Some(name.clone()),
                    None => None,
                };
                context.retain(NodeSpec {
                    kind: "event",
                    role_key: JsString::from("event:").concat(&key),
                    location: if name.is_null() {
                        operation.at("location").clone()
                    } else {
                        Json::Null
                    },
                    label,
                    function_node_id: None,
                    properties: Obj::new()
                        .with_static("emitter_key", operation.at("emitterKey").clone())
                        .with_static("event_name", name.clone()),
                })
            }
        };
        let Some(event) = event else { continue };
        events.insert(key, event.clone());
        let relation = match operation.at("kind").str() {
            "register" => "registers-listener",
            "remove" => "removes-listener",
            _ => "dispatches-candidate",
        };
        let complete = is_complete(operation.at("resolution"));
        if operation.at("kind").str() == "dispatch" {
            let emitter = context
                .binding(operation.at("emitterBindingId"))
                .or_else(|| {
                    if operation.at("ownerCallableId").is_null() {
                        Some(context.module_node.clone())
                    } else {
                        context.callable(operation.at("ownerCallableId"))
                    }
                })
                .unwrap_or_else(|| context.module_node.clone());
            context.relate(Some(&emitter), Some(&event), relation, resolution(complete));
        } else {
            let method = operation.at("method").str();
            let label = match name.as_js_string() {
                None => JsString::from(method),
                Some(name) if name.len() <= "listener".encode_utf16().count() => {
                    JsString::from(method).concat_str(":").concat(name)
                }
                Some(_) => JsString::from(format!("{method}:listener")),
            };
            let location = operation
                .get("listenerLocation")
                .filter(|location| !location.is_null())
                .unwrap_or(operation.at("location"))
                .clone();
            let function = owner_id(context, operation.at("ownerCallableId"));
            let listener = context.retain(NodeSpec {
                kind: "listener",
                role_key: format!("listener:{}", operation.at("eventId").str()).into(),
                location,
                label: Some(label.into()),
                function_node_id: function.map(Into::into),
                properties: Obj::new()
                    .with_static("emitter_key", operation.at("emitterKey").clone())
                    .with_static("event_name", name.clone())
                    .with_static("method", method),
            });
            context.relate(
                Some(&event),
                listener.as_ref(),
                relation,
                resolution(complete),
            );
        }
        if !complete {
            let detail = if name.is_null() {
                format!(
                    "Dynamic {} event name remains unresolved.",
                    operation.at("method").str()
                )
            } else {
                format!(
                    "Static {} emitter identity is partial.",
                    operation.at("method").str()
                )
            };
            let evidence = context.unknown_evidence(operation.at("location"));
            context.unknown(UnknownSpec {
                node_id: node_id(Some(&event)),
                family: "event",
                relation_kinds: vec![relation.to_owned()],
                reason: "ambiguous-target",
                detail: detail.into(),
                candidate_node_ids: Vec::new(),
                evidence,
            });
        }
    }
}

fn projected_bindings(context: &mut FileContext<'_>, source: Option<&Json>, operation: &Json) {
    for projected in operation.at("projectedResultBindings").arr() {
        let target = context.binding(projected.at("bindingId"));
        let mut spec = RelationSpec::new(
            source,
            target.as_ref(),
            "destructures",
            resolution(is_complete(projected.at("resolution"))),
        );
        spec.properties = Obj::new()
            .with_static("projection_path", projected.at("projectionPath").clone())
            .with_static("projection_resolution", projected.at("resolution").clone());
        add_relation(context.state, spec);
    }
}

/// `projectSemanticTimers`.
pub fn project_timers(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    let mut timers: HashMap<String, Json> = HashMap::new();
    for operation in ir
        .records(SemanticCollection::TimerOperations)
        .filter(|operation| operation.at("kind").str() == "schedule")
    {
        let function = owner_id(context, operation.at("ownerCallableId"));
        let timer = context.retain(NodeSpec {
            kind: "timer",
            role_key: operation.at("timerId").str().to_owned().into(),
            location: operation.at("location").clone(),
            label: Some(operation.at("method").text().clone()),
            function_node_id: function.map(Into::into),
            properties: Obj::new()
                .with_static(
                    "delay_milliseconds",
                    operation.at("delayMilliseconds").clone(),
                )
                .with_static("method", operation.at("method").clone()),
        });
        if let Some(timer) = timer {
            timers.insert(operation.at("timerId").str().to_owned(), timer);
        }
    }
    for operation in ir.records(SemanticCollection::TimerOperations) {
        let call = context.call_site_at(operation.at("location"));
        if operation.at("kind").str() == "schedule" {
            let timer = timers.get(operation.at("timerId").str()).cloned();
            context.relate(call.as_ref(), timer.as_ref(), "schedules-timer", "resolved");
            projected_bindings(context, timer.as_ref(), &operation);
            continue;
        }
        let target = operation
            .at("linkedTimerId")
            .as_str()
            .and_then(|id| timers.get(id))
            .cloned();
        let complete = is_complete(operation.at("resolution"));
        context.relate(
            call.as_ref(),
            target.as_ref(),
            "cancels-timer",
            resolution(complete),
        );
        if complete {
            continue;
        }
        let evidence = context.unknown_evidence(operation.at("location"));
        context.unknown(UnknownSpec {
            node_id: node_id(call.as_ref()),
            family: "timer",
            relation_kinds: to_strings(&["cancels-timer"]),
            reason: "ambiguous-target",
            detail: format!(
                "Static {} handle resolution was {}.",
                operation.at("method").str(),
                operation.at("resolution").str()
            )
            .into(),
            candidate_node_ids: Vec::new(),
            evidence,
        });
    }
}

// ---------------------------------------------------------------- child processes

/// `projectSemanticChildProcesses`.
pub fn project_child_processes(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    let mut processes: HashMap<String, Json> = HashMap::new();
    for spawn in ir.records(SemanticCollection::ChildProcessSpawns) {
        let function = owner_id(context, spawn.at("ownerCallableId"));
        let label = spawn
            .at("command")
            .as_js_string()
            .cloned()
            .unwrap_or_else(|| JsString::from(spawn.at("method").str()));
        let node = context.retain(NodeSpec {
            kind: "child-process",
            role_key: spawn.at("processId").str().to_owned().into(),
            location: spawn.at("location").clone(),
            label: Some(label),
            function_node_id: function.map(Into::into),
            properties: Obj::new()
                .with_static("argv_count", spawn.at("argvCount").clone())
                .with_static("command", spawn.at("command").clone())
                .with_static(
                    "environment_supplied",
                    spawn.at("environmentSupplied").clone(),
                )
                .with_static("method", spawn.at("method").clone())
                .with_static("stdio_mode", spawn.at("stdioMode").clone()),
        });
        if let Some(node) = node {
            processes.insert(spawn.at("processId").str().to_owned(), node);
        }
    }
    for spawn in ir.records(SemanticCollection::ChildProcessSpawns) {
        let Some(child) = processes.get(spawn.at("processId").str()).cloned() else {
            continue;
        };
        let call = context.call_site_at(spawn.at("location"));
        let complete = is_complete(spawn.at("resolution"));
        context.relate(call.as_ref(), Some(&child), "spawns", resolution(complete));
        projected_bindings(context, Some(&child), &spawn);
        if !spawn.at("argvCount").is_null() {
            let mut spec =
                RelationSpec::new(call.as_ref(), Some(&child), "supplies-argv", "resolved");
            spec.properties =
                Obj::new().with_static("argument_count", spawn.at("argvCount").clone());
            add_relation(context.state, spec);
        }
        if spawn.at("environmentSupplied").as_bool() == Some(true) {
            context.relate(call.as_ref(), Some(&child), "supplies-env", "resolved");
        }
        let mode = spawn.at("stdioMode").str();
        let stdio = context.retain(NodeSpec {
            kind: "stdio",
            role_key: format!("stdio:{}", spawn.at("processId").str()).into(),
            location: spawn.at("location").clone(),
            label: Some(mode.to_owned().into()),
            function_node_id: child.at("function_node_id").as_js_string().cloned(),
            properties: Obj::new().with_static("mode", mode),
        });
        context.relate(
            Some(&child),
            stdio.as_ref(),
            "connects-stdio",
            if mode == "dynamic" {
                "candidate"
            } else {
                "resolved"
            },
        );
        let method = spawn.at("method").str();
        if mode == "dynamic" {
            child_unknown(
                context,
                Some(&child),
                spawn.at("location"),
                &["connects-stdio"],
                "unknown-value",
                format!("Static {method} stdio options remain unresolved."),
                Vec::new(),
            );
        }
        if !complete {
            child_unknown(
                context,
                Some(&child),
                spawn.at("location"),
                &["spawns"],
                "ambiguous-target",
                format!("Static {method} command remains unresolved."),
                Vec::new(),
            );
        }
    }
    let ir = context.ir.clone();
    for interaction in ir.records(SemanticCollection::ChildProcessInteractions) {
        let children: Vec<Json> = interaction
            .at("linkedProcessIds")
            .arr()
            .iter()
            .filter_map(|id| processes.get(id.str()).cloned())
            .collect();
        let listener = interaction.at("kind").str() == "listener";
        let function = owner_id(context, interaction.at("ownerCallableId"));
        let effect = if listener {
            let location = interaction
                .get("listenerLocation")
                .filter(|location| !location.is_null())
                .unwrap_or(interaction.at("location"))
                .clone();
            context.retain(NodeSpec {
                kind: "listener",
                role_key: interaction.at("interactionId").str().to_owned().into(),
                location,
                label: interaction.at("eventName").as_js_string().cloned(),
                function_node_id: function.map(Into::into),
                properties: Obj::new()
                    .with_static("event_name", interaction.at("eventName").clone())
                    .with_static("method", interaction.at("method").clone()),
            })
        } else {
            context.retain(NodeSpec {
                kind: "signal",
                role_key: interaction.at("interactionId").str().to_owned().into(),
                location: interaction.at("location").clone(),
                label: interaction.at("signalName").as_js_string().cloned(),
                function_node_id: function.map(Into::into),
                properties: Obj::new()
                    .with_static("signal_name", interaction.at("signalName").clone()),
            })
        };
        let relation = if interaction.at("kind").str() == "signal" {
            "forwards-signal"
        } else if interaction.at("eventName").str() == "exit" {
            "listens-exit"
        } else {
            "listens-error"
        };
        let complete = is_complete(interaction.at("resolution"));
        for child in &children {
            if listener {
                context.relate(Some(child), effect.as_ref(), relation, resolution(complete));
            } else {
                context.relate(effect.as_ref(), Some(child), relation, resolution(complete));
            }
        }
        if !complete {
            child_unknown(
                context,
                effect.as_ref(),
                interaction.at("location"),
                &[relation],
                "ambiguous-target",
                format!(
                    "Static child {} ownership is ambiguous.",
                    interaction.at("method").str()
                ),
                children
                    .iter()
                    .map(|child| child.at("node_id").str().to_owned())
                    .collect(),
            );
        }
    }
}

fn child_unknown(
    context: &mut FileContext<'_>,
    node: Option<&Json>,
    location: &Json,
    relations: &[&str],
    reason: &str,
    detail: String,
    candidates: Vec<String>,
) {
    let evidence = context.unknown_evidence(location);
    context.unknown(UnknownSpec {
        node_id: node_id(node),
        family: "child-process",
        relation_kinds: to_strings(relations),
        reason,
        detail: detail.into(),
        candidate_node_ids: candidates,
        evidence,
    });
}

// ---------------------------------------------------------------- configuration, requests, boundaries

fn binding_or_owner(context: &FileContext<'_>, binding: &Json, callable: &Json) -> Json {
    context.binding(binding).unwrap_or_else(|| {
        if callable.is_null() {
            context.module_node.clone()
        } else {
            context
                .callable(callable)
                .unwrap_or_else(|| context.module_node.clone())
        }
    })
}

/// `addDataUnknown`: one configuration, request or boundary frontier.
struct DataUnknown<'d> {
    family: &'d str,
    relations: Vec<String>,
    reason: &'d str,
    detail: String,
    candidates: Vec<String>,
}

fn data_unknown(
    context: &mut FileContext<'_>,
    node: &Json,
    location: &Json,
    input: DataUnknown<'_>,
) {
    let evidence = context.unknown_evidence(location);
    context.unknown(UnknownSpec {
        node_id: node_id(Some(node)),
        family: input.family,
        relation_kinds: input.relations,
        reason: input.reason,
        detail: input.detail.into(),
        candidate_node_ids: input.candidates,
        evidence,
    });
}

fn configuration_relation(kind: &str) -> &'static str {
    match kind {
        "environment" => "reads-environment",
        "argv" => "reads-argv",
        "file" => "reads-config",
        _ => "defaults",
    }
}

/// `projectSemanticConfiguration`.
pub fn project_configuration(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    let mut nodes: HashMap<String, Json> = HashMap::new();
    for operation in ir.records(SemanticCollection::ConfigurationOperations) {
        let function = owner_id(context, operation.at("ownerCallableId"));
        let mut properties = Obj::new()
            .with_static("key", operation.at("key").clone())
            .with_static("source_kind", operation.at("kind").clone())
            .with_static("value", operation.at("value").clone());
        if let Some(limit) = operation.get("valueResourceLimit") {
            properties.set("value_resource_limit", limit.clone());
        }
        let node = context.retain(NodeSpec {
            kind: "config-source",
            role_key: operation.at("configId").str().to_owned().into(),
            location: operation.at("location").clone(),
            label: Some(
                operation
                    .at("key")
                    .as_js_string()
                    .cloned()
                    .unwrap_or_else(|| operation.at("kind").text().clone()),
            ),
            function_node_id: function.map(Into::into),
            properties,
        });
        if let Some(node) = node {
            nodes.insert(operation.at("configId").str().to_owned(), node);
        }
    }
    for operation in ir.records(SemanticCollection::ConfigurationOperations) {
        let Some(config) = nodes.get(operation.at("configId").str()).cloned() else {
            continue;
        };
        let kind = operation.at("kind").str();
        let target = binding_or_owner(
            context,
            operation.at("resultBindingId"),
            operation.at("ownerCallableId"),
        );
        let complete = is_complete(operation.at("resolution"));
        let relation = configuration_relation(kind);
        context.relate(Some(&config), Some(&target), relation, resolution(complete));
        if kind == "default"
            && let Some(source) = operation.at("sourceConfigId").as_str()
        {
            let source = nodes.get(source).cloned();
            context.relate(
                source.as_ref(),
                Some(&config),
                "overrides",
                resolution(complete),
            );
        }
        if !complete {
            let mut relations = vec![relation.to_owned()];
            if kind == "default" {
                relations.push("overrides".to_owned());
            }
            let (reason, detail) = match operation.get("valueResourceLimit") {
                None => (
                    "ambiguous-target",
                    if kind == "default" {
                        "Static default configuration value is partial.".to_owned()
                    } else {
                        format!("Static {kind} configuration identity is partial.")
                    },
                ),
                Some(limit) => (
                    "resource-limit",
                    semantic_resource_limit_reason(limit.str()).to_owned(),
                ),
            };
            let input = DataUnknown {
                family: "configuration",
                relations,
                reason,
                detail,
                candidates: Vec::new(),
            };
            data_unknown(context, &config, operation.at("location"), input);
        }
    }
}

/// `projectSemanticRequests`.
pub fn project_requests(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    let mut nodes: HashMap<String, Json> = HashMap::new();
    for operation in ir.records(SemanticCollection::RequestOperations) {
        let method = operation.at("method").str();
        let label = match operation.at("endpoint").as_js_string() {
            Some(endpoint) if endpoint.len() <= utf16_len(method) => endpoint.clone(),
            _ => JsString::from(method),
        };
        let function = owner_id(context, operation.at("ownerCallableId"));
        let node = context.retain(NodeSpec {
            kind: if operation.at("kind").str() == "request" {
                "request"
            } else {
                "response"
            },
            role_key: operation.at("requestId").str().to_owned().into(),
            location: operation.at("location").clone(),
            label: Some(label),
            function_node_id: function.map(Into::into),
            properties: Obj::new()
                .with_static("endpoint", operation.at("endpoint").clone())
                .with_static("method", method)
                .with_static("operation_kind", operation.at("kind").clone()),
        });
        if let Some(node) = node {
            nodes.insert(operation.at("requestId").str().to_owned(), node);
        }
    }
    for operation in ir.records(SemanticCollection::RequestOperations) {
        let Some(request) = nodes.get(operation.at("requestId").str()).cloned() else {
            continue;
        };
        let complete = is_complete(operation.at("resolution"));
        let call = context.call_site_at(operation.at("location"));
        let is_request = operation.at("kind").str() == "request";
        if is_request {
            context.relate(
                call.as_ref(),
                Some(&request),
                "constructs-request",
                resolution(complete),
            );
            projected_bindings(context, Some(&request), &operation);
            for field in operation.at("fields").arr() {
                let source = if field.at("sourceBindingId").is_null() {
                    call.clone()
                } else {
                    context.binding(field.at("sourceBindingId"))
                };
                let mut spec = RelationSpec::new(
                    source.as_ref(),
                    Some(&request),
                    "supplies-request-field",
                    if field.at("sourceBindingId").is_null() {
                        "candidate"
                    } else {
                        "resolved"
                    },
                );
                spec.properties = Obj::new().with_static("field", field.at("name").clone());
                add_relation(context.state, spec);
            }
        } else {
            let mut spec = RelationSpec::new(
                Some(&request),
                call.as_ref(),
                "consumed-by",
                resolution(complete),
            );
            spec.properties = Obj::new().with_static("method", operation.at("method").clone());
            add_relation(context.state, spec);
        }
        if !complete {
            let relations = if is_request {
                to_strings(&["constructs-request", "supplies-request-field"])
            } else {
                to_strings(&["consumed-by"])
            };
            let candidates = operation
                .at("linkedRequestIds")
                .arr()
                .iter()
                .filter_map(|id| node_id(nodes.get(id.str())))
                .collect();
            let detail = format!(
                "Static {} request resolution was {}.",
                operation.at("method").str(),
                operation.at("resolution").str()
            );
            let input = DataUnknown {
                family: "request",
                relations,
                reason: "ambiguous-target",
                detail,
                candidates,
            };
            data_unknown(context, &request, operation.at("location"), input);
        }
    }
}

/// `projectSemanticBoundaries`.
pub fn project_boundaries(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    for operation in ir.records(SemanticCollection::BoundaryOperations) {
        let function = owner_id(context, operation.at("ownerCallableId"));
        let Some(boundary) = context.retain(NodeSpec {
            kind: "boundary",
            role_key: operation.at("boundaryId").str().to_owned().into(),
            location: operation.at("location").clone(),
            label: Some(operation.at("method").text().clone()),
            function_node_id: function.map(Into::into),
            properties: Obj::new()
                .with_static("boundary_kind", operation.at("kind").clone())
                .with_static("field", operation.at("method").clone())
                .with_static("method", operation.at("method").clone()),
        }) else {
            continue;
        };
        let relation = match operation.at("kind").str() {
            "parse" => "parses",
            "coerce" => "coerces",
            _ => "validates",
        };
        let source = binding_or_owner(
            context,
            operation.at("sourceBindingId"),
            operation.at("ownerCallableId"),
        );
        let complete = is_complete(operation.at("resolution"));
        context.relate(
            Some(&source),
            Some(&boundary),
            relation,
            resolution(complete),
        );
        if !complete {
            let detail = format!(
                "Static {} boundary kind is a candidate.",
                operation.at("method").str()
            );
            let input = DataUnknown {
                family: "boundary",
                relations: vec![relation.to_owned()],
                reason: "ambiguous-target",
                detail,
                candidates: Vec::new(),
            };
            data_unknown(context, &boundary, operation.at("location"), input);
        }
    }
}

// ---------------------------------------------------------------- resources

/// `projectSemanticResources`.
pub fn project_resources(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    let mut resources: HashMap<String, Json> = HashMap::new();
    for operation in ir
        .records(SemanticCollection::ResourceOperations)
        .filter(|operation| operation.at("kind").str() == "acquire")
    {
        let function = owner_id(context, operation.at("ownerCallableId"));
        let node = context.retain(NodeSpec {
            kind: "resource",
            role_key: operation.at("resourceId").str().to_owned().into(),
            location: operation.at("location").clone(),
            label: Some(operation.at("method").text().clone()),
            function_node_id: function.map(Into::into),
            properties: Obj::new().with_static("method", operation.at("method").clone()),
        });
        if let Some(node) = node {
            resources.insert(operation.at("resourceId").str().to_owned(), node);
        }
    }
    for operation in ir.records(SemanticCollection::ResourceOperations) {
        let call = context.call_site_at(operation.at("location"));
        if operation.at("kind").str() == "acquire" {
            let target = resources.get(operation.at("resourceId").str()).cloned();
            context.relate(call.as_ref(), target.as_ref(), "acquires", "resolved");
            continue;
        }
        let linked: Vec<Json> = operation
            .at("linkedResourceIds")
            .arr()
            .iter()
            .filter_map(|id| resources.get(id.str()).cloned())
            .collect();
        let complete = is_complete(operation.at("resolution"));
        for resource in &linked {
            context.relate(
                call.as_ref(),
                Some(resource),
                "releases",
                resolution(complete),
            );
        }
        if complete {
            continue;
        }
        let evidence = context.unknown_evidence(operation.at("location"));
        context.unknown(UnknownSpec {
            node_id: node_id(call.as_ref()),
            family: "resource-lifecycle",
            relation_kinds: to_strings(&["releases"]),
            reason: "ambiguous-target",
            detail: format!(
                "Static {} resource ownership is ambiguous.",
                operation.at("method").str()
            )
            .into(),
            candidate_node_ids: linked
                .iter()
                .map(|node| node.at("node_id").str().to_owned())
                .collect(),
            evidence,
        });
    }
}

// ---------------------------------------------------------------- captures and frontiers

/// `projectSemanticClosureCaptures`.
pub fn project_closure_captures(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    for capture in ir.records(SemanticCollection::ClosureCaptures) {
        let source = context.binding(capture.at("bindingId"));
        let target = context.callable(capture.at("callableId"));
        let mut spec = RelationSpec::new(source.as_ref(), target.as_ref(), "captures", "resolved");
        spec.evidence = Some(context.inferred_evidence(capture.at("referenceLocation")));
        add_relation(context.state, spec);
    }
}

/// `projectSemanticFrontiers`.
pub fn project_frontiers(context: &mut FileContext<'_>) {
    let ir = context.ir.clone();
    for frontier in ir.records(SemanticCollection::Frontiers) {
        let kind = frontier.at("kind").str();
        let (family, relations): (&str, &[&str]) = match kind {
            "dynamic-call" => ("call-flow", &["calls"]),
            "dynamic-scope" => ("data-flow", &["reads", "writes"]),
            _ => ("object-flow", &["reads-property", "writes-property"]),
        };
        let node = context
            .callable_node_id(frontier.at("callableId"))
            .unwrap_or_else(|| context.module_node.at("node_id").str().to_owned());
        if context.state.unknown_capacity_reached() {
            context.state.record_unknown_capacity_omission(family, kind);
            continue;
        }
        let evidence = context.unknown_evidence(frontier.at("location"));
        context.unknown(UnknownSpec {
            node_id: Some(node),
            family,
            relation_kinds: to_strings(relations),
            reason: kind,
            detail: frontier.at("reason").text().clone(),
            candidate_node_ids: Vec::new(),
            evidence,
        });
    }
}

// ---------------------------------------------------------------- fingerprints and limits

/// `projectSemanticFunctionFingerprints`.
pub fn project_fingerprints(context: &mut FileContext<'_>) -> Vec<Json> {
    let ir = context.ir.clone();
    let mut output = Vec::new();
    for fingerprint in ir.records(SemanticCollection::FunctionFingerprints) {
        let Some(callable) = context.callable(fingerprint.at("callableId")) else {
            continue;
        };
        let components = fingerprint.at("components");
        let input = Obj::new()
            .with_static("function_node_id", callable.at("node_id").clone())
            .with_static("algorithm", "rea.javascript-semantic-function")
            .with_static("status", fingerprint.at("status").clone())
            .with_static(
                "components",
                Obj::new()
                    .with_static("parameter_arity", components.at("parameterArity").clone())
                    .with_static(
                        "normalized_ast_sha256",
                        components.at("normalizedAstSha256").clone(),
                    )
                    .with_static(
                        "control_flow_sha256",
                        components.at("controlFlowSha256").clone(),
                    )
                    .with_static(
                        "relation_shape_sha256",
                        components.at("relationShapeSha256").clone(),
                    )
                    .with_static(
                        "literal_set_sha256",
                        components.at("literalSetSha256").clone(),
                    )
                    .with_static("effects", components.at("effects").clone()),
            )
            .with_static("limitations", fingerprint.at("limitations").clone())
            .with_static(
                "evidence",
                context.observed_evidence(callable.at("identity").at("source_range")),
            );
        output.push(super::semantic_graph::create_fingerprint(
            context.state,
            input,
        ));
    }
    output
}

/// `projectFileResourceLimits`: getter-expansion limits without tagged values.
pub fn project_resource_limits(
    state: &mut ProjectionState,
    file: &Json,
    coverage: &Json,
    module_node: &Json,
) {
    for limit in super::leaves::semantic_resource_limits(coverage) {
        if limit != "getter-expansion" {
            continue;
        }
        let reason = semantic_resource_limit_reason(&limit);
        let mut evidence = unknown_evidence(file, &Json::Null).obj();
        evidence.set(
            "coverage",
            partial_coverage(
                semantic_resource_limit_coverage(std::slice::from_ref(&limit)),
                None,
            ),
        );
        evidence.set("limitations", strings([reason]));
        add_unknown(
            state,
            UnknownSpec {
                node_id: node_id(Some(module_node)),
                family: "data-flow",
                relation_kinds: to_strings(&["defines"]),
                reason: "resource-limit",
                detail: JsString::from(reason),
                candidate_node_ids: Vec::new(),
                evidence: evidence.into(),
            },
        );
    }
}

/// `projectElectronSemanticCallPaths`.
pub fn project_electron_paths(state: &mut ProjectionState, file: &Json, paths: &[Json]) {
    for path in paths {
        let path_id = super::json::sha256_text(&path.stringify());
        let entry_path = path.get("entry_path").cloned();
        let mut previous: Option<Json> = None;
        let mut previous_kind: Option<String> = None;
        for (index, step) in path.at("steps").arr().iter().enumerate() {
            let step_kind = step.at("kind").str();
            let mut properties = Obj::new()
                .with_static("path_id", path_id.as_str())
                .with_static("entry", path.at("entry").clone());
            if let Some(entry_path) = &entry_path {
                properties.set("entry_path", entry_path.clone());
            }
            properties.set("channel", path.at("channel").clone());
            properties.set("terminal", path.at("terminal").clone());
            properties.set("step_kind", step_kind);
            properties.set("resolution", "candidate");
            properties.set(
                "conditions",
                Json::array(
                    path.at("conditions")
                        .arr()
                        .iter()
                        .map(|condition| {
                            let location = condition.at("location");
                            Obj::new()
                                .with_static("expression", condition.at("expression").clone())
                                .with_static(
                                    "location",
                                    Obj::new()
                                        .with_static("start", location.at("start").clone())
                                        .with_static("end", location.at("end").clone()),
                                )
                                .into()
                        })
                        .collect(),
                ),
            );
            let node = retain_node(
                state,
                file,
                NodeSpec {
                    kind: match step_kind {
                        "function" => "function",
                        "exposure" => "boundary",
                        _ => "call-site",
                    },
                    role_key: format!("electron-path:{path_id}:{index}").into(),
                    location: step.at("location").clone(),
                    label: step.at("label").as_js_string().cloned(),
                    function_node_id: None,
                    properties,
                },
            );
            if index == 0
                && let Some(node) = &node
            {
                super::semantic_graph::add_root(state, node.at("node_id").str());
            }
            let relation = match previous_kind.as_deref() {
                Some("ipc") => "registers-listener",
                Some("exposure" | "factory") => "aliases",
                _ => "calls",
            };
            let mut relation_properties = Obj::new()
                .with_static("path_id", path_id.as_str())
                .with_static("entry", path.at("entry").clone());
            if let Some(entry_path) = &entry_path {
                relation_properties.set("entry_path", entry_path.clone());
            }
            relation_properties.set("channel", path.at("channel").clone());
            relation_properties.set("basis", "lexical-wrapper-substitution");
            let mut spec =
                RelationSpec::new(previous.as_ref(), node.as_ref(), relation, "candidate");
            spec.evidence = Some(inferred_evidence_at(file, step.at("location")));
            spec.properties = relation_properties;
            add_relation(state, spec);
            previous = node;
            previous_kind = Some(step_kind.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_path_keeps_unpaired_units_and_pointer_escaping() {
        let path: Json = Json::array(vec![
            Json::from(JsString::from_utf16(vec![0x0078, 0xd800, 0x0079])),
            Json::from(JsString::from("a/b~c")),
        ]);
        let exact = js_string_path(&path);
        let pointer = property_pointer_js(&exact);

        assert_eq!(exact[0].units(), &[0x0078, 0xd800, 0x0079]);
        assert_eq!(exact[1].as_str(), Some("a/b~c"));
        assert_eq!(
            pointer.units(),
            &[
                b'/' as u16,
                b'x' as u16,
                0xd800,
                b'y' as u16,
                b'/' as u16,
                b'a' as u16,
                b'~' as u16,
                b'1' as u16,
                b'b' as u16,
                b'~' as u16,
                b'0' as u16,
                b'c' as u16,
            ]
        );
    }
}
