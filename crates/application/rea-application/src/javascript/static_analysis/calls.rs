//! Call, reference, endpoint, storage, and role findings.
//!
//! This module mirrors the call-oriented part of
//! `javascriptStaticAnalysisCalls.ts`.  It intentionally owns classification
//! only; binding and mutation proofs remain in the semantic state and parser.

use std::collections::HashSet;

use crate::javascript::ast::{AstContext, Field, Node};
use crate::javascript::contracts::static_analysis::{
    EndpointKind, PathContext, ReferenceKind, Role, RolePath, SourceMapUrl, SourceRange,
    StaticEndpoint, StaticReference, StaticStorage, StorageKind,
};
use crate::javascript::semantic::ambient_writes::is_unmodified_import_meta_url;
use crate::javascript::semantic::ast_values::unwrapped;
use crate::javascript::semantic::ast_values::{
    ExactLiteral, read_exact_literal, static_property_name,
};
use crate::javascript::semantic::globals::{is_unmodified_global_reference, member_path};
use crate::javascript::semantic::map_operations::is_intrinsic_map_lookup;
use crate::javascript::semantic::opaque_effects::index_opaque_effects;
use crate::javascript::semantic::require_origin::{RequireLoaderFact, require_loader_at};
use crate::javascript::semantic::state::SemanticState;
use crate::javascript::semantic::value_types::JsString;
use crate::javascript::semantic::value_types::Primitive;
use crate::javascript::semantic::values::evaluate_semantic_expression;

use super::helpers::{
    self, EndpointKind as HelperEndpointKind, STATIC_ROUTE_CALL_NAMES, StaticPathContext,
};

#[derive(Default)]
pub struct CallFindings {
    pub references: Vec<StaticReference>,
    pub endpoints: Vec<StaticEndpoint>,
    pub storage: Vec<StaticStorage>,
    pub role_paths: Vec<RolePath>,
    pub source_map_urls: Vec<SourceMapUrl>,
    pub unknown_findings: u64,
}

pub fn collect_calls<'a>(
    state: &'a SemanticState<'a>,
    nodes: &[Node<'a>],
    factory_require_binding_ids: &[String],
) -> CallFindings {
    let context = &state.context;
    let opaque_effects = index_opaque_effects(state);
    let mut findings = CallFindings::default();
    for node in nodes {
        collect_module_reference(context, *node, &mut findings);
        collect_call(
            context,
            state,
            &opaque_effects,
            factory_require_binding_ids,
            *node,
            &mut findings,
        );
        collect_role_property(state, *node, &mut findings);
    }
    findings.source_map_urls = collect_source_map_urls(context);
    findings
}

/// Returns whether the TypeScript pipeline would request its whole-source
/// member-mutation index for these calls.
///
/// The index is an input to the pending network, SQLite, and named
/// `get`/`delete` receivers.  Running it for every source file also walks
/// unrelated returned references and widens their limitations, so the
/// orchestrator must decide whether one of those consumers exists first.
pub fn requires_member_mutation_facts<'a>(state: &SemanticState<'a>, nodes: &[Node<'a>]) -> bool {
    let has_named_lookup = nodes.iter().copied().any(|node| {
        if !matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression" | "NewExpression"
        ) {
            return false;
        }
        let Some(callee) = node.field(state.source, Field::Callee) else {
            return false;
        };
        let name = helpers::callee_name(&state.context, callee);
        name.ends_with(".get") || name.ends_with(".delete")
    });
    let opaque_effects = has_named_lookup.then(|| index_opaque_effects(state));

    nodes.iter().copied().any(|node| {
        if !matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression" | "NewExpression"
        ) {
            return false;
        }
        let Some(callee) = node.field(state.source, Field::Callee) else {
            return false;
        };
        let name = helpers::callee_name(&state.context, callee);
        let arguments = node.field_list(state.source, Field::Arguments);
        let first = arguments.first().copied().flatten();

        if name == "Database" || name.ends_with(".Database") {
            return true;
        }

        if is_known_network_call(state, callee, &name) {
            let Some(first) = first else {
                return false;
            };
            let target = request_reference_target(state.source, first);
            return literal_string(state.source, Some(target)).is_none()
                && matches!(
                    target.babel_type(),
                    "Identifier" | "MemberExpression" | "OptionalMemberExpression"
                );
        }

        if !(name.ends_with(".get") || name.ends_with(".delete")) || first.is_none() {
            return false;
        }

        // Match the TypeScript pending-network predicate: only a receiver
        // that looks like an endpoint candidate and whose intrinsic Map
        // identity is still unknown needs the mutation index.
        helpers::endpoint_argument(&state.context, &name, &arguments, callee, None).is_some()
            && opaque_effects.as_ref().is_some_and(|effects| {
                is_intrinsic_map_lookup(node, state, effects, None).is_none()
            })
    })
}

fn request_reference_target<'a>(source: &'a str, node: Node<'a>) -> Node<'a> {
    let target = unwrapped(source, node);
    if !matches!(
        target.babel_type(),
        "CallExpression" | "OptionalCallExpression"
    ) || !target.field_list(source, Field::Arguments).is_empty()
    {
        return target;
    }

    let Some(callee) = target.field(source, Field::Callee) else {
        return target;
    };
    let Some(property) = callee.field(source, Field::Property) else {
        return target;
    };
    if static_property_name(source, property, callee.computed()) != "toString" {
        return target;
    }
    callee
        .field(source, Field::Object)
        .map(|object| unwrapped(source, object))
        .unwrap_or(target)
}

fn collect_module_reference<'a>(
    context: &AstContext<'a>,
    node: Node<'a>,
    findings: &mut CallFindings,
) {
    let source = context.source();
    let (kind, value) = match node.babel_type() {
        "ImportDeclaration" | "ExportAllDeclaration" | "ExportNamedDeclaration" => {
            let Some(source_node) = node.field(source, Field::Source) else {
                return;
            };
            (
                ReferenceKind::StaticImport,
                literal_string(source, Some(source_node)),
            )
        }
        "ImportExpression" => {
            let value = node
                .field(source, Field::Source)
                .and_then(|node| literal_string(source, Some(node)));
            (ReferenceKind::DynamicImport, value)
        }
        "TSImportEqualsDeclaration" => {
            if node.import_kind() == Some("type") {
                return;
            }
            let Some(value) = node
                .field(source, Field::ModuleReference)
                .and_then(|reference| {
                    reference
                        .field(source, Field::Expression)
                        .and_then(|expression| literal_string(source, Some(expression)))
                })
            else {
                // `import x = Namespace.Member` is a TypeScript binding,
                // not a runtime module dependency. Only the external-module
                // form, `import x = require("module")`, belongs in the
                // require reference stream.
                return;
            };
            (ReferenceKind::Require, Some(value))
        }
        _ => return,
    };
    let expression = value
        .is_none()
        .then(|| JsString::from(helpers::source_slice(context, &node)));
    push_reference(
        findings,
        kind,
        value,
        expression,
        helpers::range(context, &node),
    );
}

fn collect_call<'a>(
    context: &AstContext<'a>,
    state: &SemanticState<'a>,
    opaque_effects: &crate::javascript::semantic::opaque_effects::OpaqueEffects<'a>,
    factory_require_binding_ids: &[String],
    node: Node<'a>,
    findings: &mut CallFindings,
) {
    if !matches!(
        node.babel_type(),
        "CallExpression" | "OptionalCallExpression" | "NewExpression"
    ) {
        return;
    }
    let source = context.source();
    let Some(callee) = node.field(source, Field::Callee) else {
        return;
    };
    let name = helpers::callee_name(context, callee);
    let args = node.field_list(source, Field::Arguments);
    let first = args.first().copied().flatten();
    let location = helpers::range(context, &node);
    let source_expression = Some(JsString::from(helpers::source_slice(context, &node)));

    let loader = unwrapped(source, callee);
    let factory_owned = loader
        .identifier_name()
        .and_then(|name| state.resolve_binding(&loader, name))
        .is_some_and(|index| {
            factory_require_binding_ids.contains(&state.binding(index).binding_id)
        });
    let require_fact = (!factory_owned && loader.identifier_name() == Some("require"))
        .then(|| require_loader_at(state, node, factory_require_binding_ids))
        .unwrap_or(RequireLoaderFact::Local);
    match require_fact {
        RequireLoaderFact::CommonJsLoader | RequireLoaderFact::CreateRequire => {
            let specifier = literal_string(source, first);
            let expression = specifier
                .is_none()
                .then(|| JsString::from(helpers::source_slice(context, &node)));
            push_reference(
                findings,
                ReferenceKind::Require,
                specifier,
                expression,
                location,
            );
        }
        RequireLoaderFact::Unknown => {
            findings.unknown_findings += 1;
            push_reference(
                findings,
                ReferenceKind::Require,
                literal_string(source, first),
                Some(JsString::from(helpers::source_slice(context, &node))),
                location,
            );
        }
        // Bundler runtime collection owns factory loader references, including
        // nonstandard parameter names and member forms.
        RequireLoaderFact::FactoryLoader | RequireLoaderFact::Local => {}
    }
    if node.babel_type() == "NewExpression" {
        let known_worker = is_unmodified_global_reference(state, &callee, "Worker");
        if known_worker || name == "Worker" || name.ends_with(".Worker") {
            let specifier = known_worker
                .then(|| module_url_specifier(state, first))
                .flatten();
            push_reference(
                findings,
                ReferenceKind::Worker,
                specifier.clone(),
                specifier
                    .is_none()
                    .then_some(source_expression.clone())
                    .flatten(),
                location,
            );
        }
    } else if is_service_worker_register(state, callee) {
        let specifier = module_url_specifier(state, first);
        push_reference(
            findings,
            ReferenceKind::ServiceWorker,
            specifier.clone(),
            specifier.is_none().then_some(source_expression).flatten(),
            location,
        );
    }

    if is_route_call(&name) {
        if let Some(value) = literal_string(source, first) {
            findings.endpoints.push(StaticEndpoint {
                module_key: None,
                location,
                kind: EndpointKind::Route,
                value,
                mechanism: format!("call:{name}"),
                interpretation: None,
                resolution: None,
                module_runtime: None,
            });
        }
    } else if let Some(endpoint) =
        endpoint(state, opaque_effects, context, &name, &args, callee, node)
    {
        findings.endpoints.push(StaticEndpoint {
            module_key: None,
            location,
            kind: match endpoint.0 {
                HelperEndpointKind::Endpoint => EndpointKind::Network,
                HelperEndpointKind::Candidate => EndpointKind::Network,
            },
            value: JsString::from(endpoint.1),
            mechanism: format!("call:{name}"),
            interpretation: (endpoint.0 == HelperEndpointKind::Candidate)
                .then(|| "candidate".to_owned()),
            resolution: None,
            module_runtime: None,
        });
    } else if is_known_network_call(state, callee, &name) {
        if let Some(target) = first {
            if let Some(value) = semantic_string_value(state, target) {
                findings.endpoints.push(StaticEndpoint {
                    module_key: None,
                    location,
                    kind: EndpointKind::Network,
                    value,
                    mechanism: format!("call:{name}"),
                    interpretation: None,
                    resolution: None,
                    module_runtime: None,
                });
                return;
            }
            let expression = helpers::source_slice(context, &target);
            findings.endpoints.push(StaticEndpoint {
                module_key: None,
                location,
                kind: EndpointKind::Network,
                value: JsString::from(expression),
                mechanism: format!("call:{name}"),
                interpretation: None,
                resolution: Some("partial".to_owned()),
                module_runtime: None,
            });
        }
    }

    if let Some(kind) = helpers::storage_kind(&name) {
        findings.storage.push(StaticStorage {
            module_key: None,
            location,
            kind: match kind {
                helpers::StorageKind::LocalStorage => StorageKind::LocalStorage,
                helpers::StorageKind::SessionStorage => StorageKind::SessionStorage,
                helpers::StorageKind::IndexedDb => StorageKind::IndexedDb,
                helpers::StorageKind::CacheStorage => StorageKind::CacheStorage,
            },
            interpretation: None,
            name: literal_string(source, first),
            mechanism: format!("call:{name}"),
            module_runtime: None,
        });
    }

    if let Some(known_sqlite) = sqlite_constructor_fact(state, callee, &name) {
        findings.storage.push(StaticStorage {
            module_key: None,
            location,
            kind: StorageKind::Sqlite,
            interpretation: (!known_sqlite).then(|| "candidate".to_owned()),
            name: literal_string(source, first),
            mechanism: format!("call:{name}"),
            module_runtime: None,
        });
    }

    if name == "loadFile"
        || name.ends_with(".loadFile")
        || name == "loadURL"
        || name.ends_with(".loadURL")
    {
        if let Some(argument) = first {
            if let Some(path) = static_role_path(context, argument) {
                let resolution_context = if name == "loadFile" || name.ends_with(".loadFile") {
                    // Electron's loadFile contract interprets even a raw
                    // relative literal as a filesystem path.  The generic
                    // path classifier intentionally leaves such literals as
                    // module specifiers, so preserve the API-specific
                    // interpretation at this producer boundary.
                    PathContext::FilesystemExpression
                } else {
                    match helpers::static_path_resolution_context(context, argument) {
                        StaticPathContext::ModuleSpecifier => PathContext::ModuleSpecifier,
                        StaticPathContext::FilesystemExpression => {
                            PathContext::FilesystemExpression
                        }
                    }
                };
                findings.role_paths.push(RolePath {
                    module_key: None,
                    location,
                    role: Role::Renderer,
                    path: JsString::from(path),
                    resolution_context,
                    mechanism: format!("call:{name}"),
                    module_runtime: None,
                });
            }
        }
    }
}

fn collect_role_property<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    findings: &mut CallFindings,
) {
    if node.babel_type() != "ObjectProperty" {
        return;
    }
    let context = &state.context;
    let source = context.source();
    let Some(key) = node.field(source, Field::Key) else {
        return;
    };
    let key_name = static_property_name(source, key, node.computed())
        .try_to_string()
        .ok();
    if matches!(key_name.as_deref(), Some("path" | "route")) {
        if let Some(value) = literal_string(source, node.field(source, Field::Value)) {
            findings.endpoints.push(StaticEndpoint {
                module_key: None,
                location: helpers::range(context, &node),
                kind: EndpointKind::Route,
                value,
                mechanism: format!("property:{}", key_name.as_deref().unwrap_or("path")),
                interpretation: None,
                resolution: None,
                module_runtime: None,
            });
        }
    }
    if static_property_name(source, key, node.computed())
        .try_to_string()
        .ok()
        .as_deref()
        != Some("preload")
    {
        return;
    }
    let Some(value) = node.field(source, Field::Value) else {
        return;
    };
    if is_media_preload_property(state, node) {
        return;
    }
    let Some(path) = static_role_path(context, value) else {
        return;
    };
    let resolution_context = match helpers::static_path_resolution_context(context, value) {
        StaticPathContext::ModuleSpecifier => PathContext::ModuleSpecifier,
        StaticPathContext::FilesystemExpression => PathContext::FilesystemExpression,
    };
    findings.role_paths.push(RolePath {
        module_key: None,
        location: helpers::range(context, &node),
        role: Role::Preload,
        path: JsString::from(path),
        resolution_context,
        mechanism: "property:preload".to_owned(),
        module_runtime: None,
    });
}

/// Preserve literal UTF-16 units before falling back to the broader path
/// evaluator, whose legacy filesystem operations return UTF-8 strings.
fn static_role_path<'a>(context: &AstContext<'a>, node: Node<'a>) -> Option<JsString> {
    if let Some(ExactLiteral::String(value)) = read_exact_literal(context.source(), node) {
        return Some(value);
    }
    helpers::static_path(context, node).map(JsString::from)
}

fn is_media_preload_property<'a>(state: &SemanticState<'a>, property: Node<'a>) -> bool {
    let Some(parent) = state.parent_of(&property) else {
        return false;
    };
    if !matches!(
        parent.babel_type(),
        "CallExpression" | "OptionalCallExpression" | "NewExpression"
    ) {
        return false;
    }
    let Some(callee) = parent.field(state.source, Field::Callee) else {
        return false;
    };
    let name = helpers::callee_name(&state.context, callee);
    if !(name == "createElement" || name.ends_with(".createElement") || name == "jsx") {
        return false;
    }
    let arguments = parent.field_list(state.source, Field::Arguments);
    matches!(
        arguments.first().copied().flatten().and_then(|argument| literal_string(state.source, Some(argument))),
        Some(value) if value == "audio" || value == "video"
    )
}

fn endpoint<'a>(
    state: &SemanticState<'a>,
    opaque_effects: &crate::javascript::semantic::opaque_effects::OpaqueEffects<'a>,
    context: &AstContext<'a>,
    name: &str,
    args: &[Option<Node<'a>>],
    callee: Node<'a>,
    node: Node<'a>,
) -> Option<(HelperEndpointKind, String)> {
    if !is_known_endpoint_identity(state, callee, name) {
        return None;
    }
    let found = helpers::endpoint_argument(context, name, args, callee, None)?;
    if found.value.is_empty()
        && args
            .first()
            .copied()
            .flatten()
            .and_then(|argument| literal_string(context.source(), Some(argument)))
            .is_none()
    {
        return None;
    }

    if found.kind == HelperEndpointKind::Candidate
        && found.value.ends_with('.')
        && found.value != "."
    {
        return None;
    }

    if found.kind == HelperEndpointKind::Candidate
        && (name.ends_with(".get") || name.ends_with(".delete"))
    {
        match is_intrinsic_map_lookup(node, state, opaque_effects, None) {
            Some(false) => {}
            Some(true) | None => return None,
        }
    }

    Some((found.kind, found.value.to_owned()))
}

fn is_route_call(name: &str) -> bool {
    STATIC_ROUTE_CALL_NAMES
        .iter()
        .any(|candidate| name == *candidate || name.ends_with(&format!(".{candidate}")))
}

fn is_known_endpoint_identity<'a>(state: &SemanticState<'a>, callee: Node<'a>, name: &str) -> bool {
    match name {
        "fetch" => is_unmodified_global_reference(state, &callee, "fetch"),
        "WebSocket" => is_unmodified_global_reference(state, &callee, "WebSocket"),
        "EventSource" => is_unmodified_global_reference(state, &callee, "EventSource"),
        "navigator.sendBeacon" => {
            let (root, members) = member_path(state.source, callee);
            state.is_unshadowed_global(&root, "navigator")
                && members.as_slice() == [Some("sendBeacon".into())]
        }
        _ => true,
    }
}

fn is_known_network_call<'a>(state: &SemanticState<'a>, callee: Node<'a>, name: &str) -> bool {
    matches!(
        name,
        "fetch" | "WebSocket" | "EventSource" | "navigator.sendBeacon"
    ) && is_known_endpoint_identity(state, callee, name)
}

fn is_service_worker_register<'a>(state: &SemanticState<'a>, callee: Node<'a>) -> bool {
    let (root, members) = member_path(state.source, callee);
    state.is_unshadowed_global(&root, "navigator")
        && matches!(
            members.as_slice(),
            [Some(first), Some(second)] if first == "serviceWorker" && second == "register"
        )
}

fn sqlite_constructor_fact<'a>(
    state: &SemanticState<'a>,
    callee: Node<'a>,
    name: &str,
) -> Option<bool> {
    if name == "Database" {
        let Some(binding) = state.resolve_binding(&callee, "Database") else {
            return state
                .is_unshadowed_global(&callee, "Database")
                .then_some(false);
        };
        return state
            .binding(binding)
            .direct_origins
            .iter()
            .any(is_sqlite_origin)
            .then_some(true);
    }

    if !name.ends_with(".Database") {
        return None;
    }
    let Some(object) = callee.field(state.source, Field::Object) else {
        return None;
    };
    let Some(identifier) = object.identifier_name() else {
        return None;
    };
    let Some(binding) = state.resolve_binding(&object, identifier) else {
        return None;
    };
    state
        .binding(binding)
        .direct_origins
        .iter()
        .any(|origin| {
            is_sqlite_origin(origin)
                && origin
                    .imported_path
                    .last()
                    .is_some_and(|member| member == "Database")
        })
        .then_some(true)
}

fn is_sqlite_origin(origin: &crate::javascript::semantic::state::ModuleOrigin) -> bool {
    origin.specifier == "sqlite3" || origin.specifier == "better-sqlite3"
}

fn literal_string(source: &str, node: Option<Node<'_>>) -> Option<JsString> {
    let node = node?;
    match read_exact_literal(source, node)? {
        ExactLiteral::String(value) => Some(value),
        _ => None,
    }
}

fn semantic_string_value<'a>(state: &SemanticState<'a>, node: Node<'a>) -> Option<JsString> {
    match evaluate_semantic_expression(node, state, None) {
        crate::javascript::semantic::value_types::SemanticValue::Literal {
            value: Primitive::String(value),
        } => Some(value),
        crate::javascript::semantic::value_types::SemanticValue::Union { values } => {
            let [Primitive::String(value)] = values.as_slice() else {
                return None;
            };
            Some(value.clone())
        }
        _ => None,
    }
}

fn module_url_specifier<'a>(
    state: &SemanticState<'a>,
    argument: Option<Node<'a>>,
) -> Option<JsString> {
    let argument = unwrapped(state.source, argument?);
    if argument.babel_type() != "NewExpression" {
        return None;
    }
    let callee = argument.field(state.source, Field::Callee)?;
    if !is_unmodified_global_reference(state, &callee, "URL") {
        return None;
    }
    let url_base = argument
        .field_list(state.source, Field::Arguments)
        .get(1)
        .copied()
        .flatten()?;
    if !is_unmodified_import_meta_url(state, url_base) {
        return None;
    }
    let specifier = literal_string(
        state.source,
        argument
            .field_list(state.source, Field::Arguments)
            .first()
            .copied()
            .flatten(),
    )?;
    let text = specifier.as_str()?.to_owned();
    let pathname = text.split(['?', '#']).next().unwrap_or("");
    if pathname.is_empty()
        || pathname.starts_with('/')
        || pathname
            .match_indices('%')
            .any(|(offset, _)| !valid_percent_escape(pathname, offset))
    {
        return None;
    }
    Some(specifier)
}

fn valid_percent_escape(value: &str, offset: usize) -> bool {
    let bytes = value.as_bytes();
    bytes
        .get(offset + 1)
        .zip(bytes.get(offset + 2))
        .is_some_and(|(left, right)| left.is_ascii_hexdigit() && right.is_ascii_hexdigit())
}

fn push_reference(
    findings: &mut CallFindings,
    kind: ReferenceKind,
    specifier: Option<JsString>,
    expression: Option<JsString>,
    location: SourceRange,
) {
    findings.references.push(StaticReference {
        module_key: None,
        location,
        kind,
        specifier,
        expression,
        module_runtime: None,
    });
}

fn collect_source_map_urls(context: &AstContext<'_>) -> Vec<SourceMapUrl> {
    let source = context.source();
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for comment in context.comments() {
        let comment_start = comment.span.start as usize;
        let comment_end = comment.content_span().end as usize;
        let Some(comment_source) = source.get(comment_start..comment_end) else {
            continue;
        };
        // The parser owns the delimiters and boundaries. A source-map
        // annotation is valid only when its marker is the first token in the
        // comment; this keeps examples in prose and quoted text inert.
        if !(comment_source.starts_with("//#")
            || comment_source.starts_with("//@")
            || comment_source.starts_with("/*#")
            || comment_source.starts_with("/*@"))
        {
            continue;
        }
        let body_start = 3;
        let body = &comment_source[body_start..];
        let Some(name_offset) = body.find(|character: char| !is_javascript_whitespace(character))
        else {
            continue;
        };
        let name_start = body_start + name_offset;
        if !comment_source[name_start..].starts_with("sourceMappingURL") {
            continue;
        }
        let name_end = name_start + "sourceMappingURL".len();
        let Some(equal_offset) =
            comment_source[name_end..].find(|character: char| !is_javascript_whitespace(character))
        else {
            continue;
        };
        let equal_start = name_end + equal_offset;
        if comment_source.as_bytes().get(equal_start) != Some(&b'=') {
            continue;
        }
        let value = &comment_source[equal_start + 1..];
        let Some(url_offset) = value.find(|character: char| !is_javascript_whitespace(character))
        else {
            continue;
        };
        let declared_start = equal_start + 1 + url_offset;
        let declared_end = comment_source[declared_start..]
            .find(is_javascript_whitespace)
            .map_or(comment_source.len(), |relative| declared_start + relative);
        if declared_start == declared_end {
            continue;
        }
        let declared = &comment_source[declared_start..declared_end];
        if seen.insert(declared.to_owned()) {
            let absolute_end = comment_start + declared_end;
            // Comment spans are parser-owned UTF-8 byte offsets. Convert
            // those offsets through the AST context; the generic offset
            // helper accepts UTF-16 offsets and would drift after any
            // non-ASCII text earlier in the file.
            let location = SourceRange {
                start: context.point_for_offset(comment_start as u32).into(),
                end: context.point_for_offset(absolute_end as u32).into(),
            };
            results.push(SourceMapUrl {
                declared_url: JsString::from(declared),
                location,
            });
        }
    }
    results
}

/// ECMAScript `\s`, used by the TypeScript directive parser for token
/// separation and URL termination. Rust's `char::is_whitespace` omits the
/// byte-order mark, which JavaScript treats as whitespace.
fn is_javascript_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}
