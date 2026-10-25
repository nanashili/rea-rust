//! Port of `javascriptStaticAnalysisBundler.ts`: Webpack/Rspack chunk
//! registrations, standalone Webpack bootstraps and esbuild wrappers, with
//! their literal module tables.

use std::collections::{BTreeSet, HashSet};
use std::ops::ControlFlow;

use super::bootstrap::javascript_bootstrap_at;
use super::findings::{ModuleRange, add_finding_once};
use super::fingerprint::{collect_javascript_exports, fingerprint_javascript_ast};
use super::helpers::{
    argument_value, callee_name, chunk_runtime, factory_require_name, module_factory,
    module_property_name, range, registration_key, sha256_text, source_slice, static_array_values,
};
use super::semantics::StaticSemantics;
use super::state::StaticAccumulator;
use crate::javascript::ast::{AstContext, AstVisitor, Field, Node, traverse};
use crate::javascript::contracts::static_analysis::{
    Bundler, BundlerModule, BundlerRegistration, JAVASCRIPT_AST_FINGERPRINT_ALGORITHM,
    RuntimeModuleCacheStatus,
};
use crate::javascript::semantic::ast_values::{
    is_function, is_member, runtime_function_parameters, static_property_key, unwrapped,
};

/// `JavaScriptRequireLoaderFact`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequireLoaderFact {
    FactoryLoader,
    Unknown,
}

/// `semanticFactoryLoaderMemberAt` (owner: `javascriptSemanticRequireOrigin`;
/// move it there when package D2 lands): whether a call or `new` invokes a
/// proven factory loader, or its `member` (for example `e`).
pub fn factory_loader_member_at<'a>(
    source: &'a str,
    node: &Node<'a>,
    semantics: &dyn StaticSemantics<'a>,
    binding_ids: &HashSet<String>,
    member: Option<&str>,
) -> Option<RequireLoaderFact> {
    let callee = unwrapped(source, node.field(source, Field::Callee)?);
    let loader = match member {
        None => Some(callee).filter(|it| it.babel_type() == "Identifier"),
        Some(member) => {
            let matches = is_member(&callee)
                && callee
                    .field(source, Field::Property)
                    .and_then(|property| static_property_key(source, property, callee.computed()))
                    .is_some_and(|property| property == member);
            if matches {
                callee
                    .field(source, Field::Object)
                    .map(|object| unwrapped(source, object))
                    .filter(|root| root.babel_type() == "Identifier")
            } else {
                None
            }
        }
    }?;
    let binding = semantics.binding(&loader)?;
    if !binding_ids.contains(&binding.binding_id) {
        return None;
    }
    // A factory parameter is a loader only while its binding has the single
    // parameter definition and no initializer.  An assignment such as
    // `loader = userInput` adds a definition; retaining the factory identity
    // after that write would turn an unknown require into a proven reference.
    Some(if binding.initializers == 0 && binding.definitions == 1 {
        RequireLoaderFact::FactoryLoader
    } else {
        RequireLoaderFact::Unknown
    })
}

struct StaticValues {
    values: Vec<String>,
    unknown: u64,
}

fn unique_values(values: Vec<String>, unknown: u64) -> StaticValues {
    let unique: BTreeSet<String> = values.into_iter().collect();
    StaticValues {
        values: unique.into_iter().collect(),
        unknown,
    }
}

struct Recovered {
    modules: Vec<BundlerModule>,
    async_chunk_keys: Vec<String>,
    unknown_async_chunk_keys: u64,
}

struct RuntimeMetadata {
    require_name: Option<String>,
    entry_module_keys: Vec<String>,
    unknown_entry_module_keys: u64,
    async_chunk_keys: Vec<String>,
    unknown_async_chunk_keys: u64,
}

fn is_bundler_function(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "FunctionExpression" | "ArrowFunctionExpression" | "ObjectMethod"
    )
}

fn sorted_modules(mut modules: Vec<BundlerModule>) -> Vec<BundlerModule> {
    modules.sort_by(|left, right| left.module_key.cmp(&right.module_key));
    modules
}

fn push_registration(accumulator: &mut StaticAccumulator, registration: BundlerRegistration) {
    let key = format!("registration\0{}", registration_key(&registration));
    let registrations = &mut accumulator.registrations;
    add_finding_once(&mut accumulator.seen, key, || {
        registrations.push(registration)
    });
}

/// `inspectBundlerRegistration`: a Webpack/Rspack chunk `push` call and its
/// module table.
pub fn inspect_bundler_registration<'a>(
    cx: &AstContext<'a>,
    call: &Node<'a>,
    accumulator: &mut StaticAccumulator,
    semantics: &dyn StaticSemantics<'a>,
) {
    let source = cx.source();
    let Some(runtime) = chunk_runtime(cx, call) else {
        return;
    };
    let Some(entry) = call
        .field_list(source, Field::Arguments)
        .first()
        .copied()
        .flatten()
        .filter(|entry| entry.babel_type() == "ArrayExpression")
    else {
        return;
    };
    let elements = entry.field_list(source, Field::Elements);
    let element = |index: usize| elements.get(index).copied().flatten();
    let runtime_value = runtime_metadata(cx, element(2), semantics, accumulator);
    let (Some(chunk_ids), Some(table)) = (
        element(0).filter(|it| it.babel_type() == "ArrayExpression"),
        element(1).filter(|it| it.babel_type() == "ObjectExpression"),
    ) else {
        return;
    };
    let recovered = recover_bundler_modules(cx, &table, accumulator, &runtime, semantics);
    let chunk_keys = static_array_values(cx, &chunk_ids);
    accumulator.unknown_findings += chunk_keys.unknown;
    accumulator.unknown_findings += runtime_value.unknown_entry_module_keys
        + runtime_value.unknown_async_chunk_keys
        + recovered.unknown_async_chunk_keys;
    let mut async_keys = runtime_value.async_chunk_keys;
    async_keys.extend(recovered.async_chunk_keys);
    let registration = BundlerRegistration {
        bundler: if runtime.to_lowercase().contains("rspack") {
            Bundler::Rspack
        } else {
            Bundler::Webpack
        },
        runtime,
        chunk_keys: chunk_keys.values,
        unknown_chunk_keys: chunk_keys.unknown,
        runtime_require_name: runtime_value.require_name,
        // A name in the source does not establish cache behavior; until the
        // runtime body proves cache reads and writes, keep the unknown.
        runtime_module_cache_status: RuntimeModuleCacheStatus::NotObserved,
        entry_module_keys: runtime_value.entry_module_keys,
        unknown_entry_module_keys: runtime_value.unknown_entry_module_keys,
        async_chunk_keys: unique_values(async_keys, 0).values,
        unknown_async_chunk_keys: runtime_value.unknown_async_chunk_keys
            + recovered.unknown_async_chunk_keys,
        modules: sorted_modules(recovered.modules),
        location: range(cx, call),
    };
    push_registration(accumulator, registration);
}

/// `inspectBundlerBootstrap`: standalone Webpack tables whose factories are
/// called by a local loader.
pub fn inspect_bundler_bootstrap<'a>(
    cx: &AstContext<'a>,
    call: &Node<'a>,
    accumulator: &mut StaticAccumulator,
    semantics: &dyn StaticSemantics<'a>,
) {
    let source = cx.source();
    let Some(bootstrap) = javascript_bootstrap_at(cx, call, semantics) else {
        return;
    };
    let start = cx.start(call);
    let runtime = format!("webpack-bootstrap@{start}");
    let recovered = recover_bundler_modules(cx, &bootstrap.table, accumulator, &runtime, semantics);
    struct Entries<'s, 'a> {
        source: &'a str,
        semantics: &'s dyn StaticSemantics<'a>,
        loader: &'s str,
        entries: Vec<String>,
        unknown: u64,
    }
    impl<'a> AstVisitor<'a> for Entries<'_, 'a> {
        fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
            if node.babel_type() != "CallExpression" || ancestors.iter().any(is_function) {
                return;
            }
            let Some(callee) = node
                .field(self.source, Field::Callee)
                .filter(|it| it.babel_type() == "Identifier")
            else {
                return;
            };
            if self.semantics.binding_id(&callee) != Some(self.loader) {
                return;
            }
            let first = node
                .field_list(self.source, Field::Arguments)
                .first()
                .copied()
                .flatten();
            match argument_value(self.source, first) {
                Some(value) => self.entries.push(value.into_owned()),
                None => self.unknown += 1,
            }
        }
    }
    let mut visitor = Entries {
        source,
        semantics,
        loader: &bootstrap.loader_binding_id,
        entries: Vec::new(),
        unknown: 0,
    };
    let _: ControlFlow<()> = traverse(bootstrap.body, source, &mut visitor, || {
        ControlFlow::Continue(())
    });
    let unknown_entries = visitor.unknown;
    let registration = BundlerRegistration {
        bundler: Bundler::Webpack,
        runtime,
        chunk_keys: vec![format!("bootstrap@{start}")],
        unknown_chunk_keys: 0,
        runtime_require_name: Some(bootstrap.loader_name.clone()),
        runtime_module_cache_status: RuntimeModuleCacheStatus::NotObserved,
        entry_module_keys: unique_values(visitor.entries, 0).values,
        unknown_entry_module_keys: unknown_entries,
        async_chunk_keys: recovered.async_chunk_keys,
        unknown_async_chunk_keys: recovered.unknown_async_chunk_keys,
        modules: sorted_modules(recovered.modules),
        location: range(cx, call),
    };
    accumulator.unknown_findings += unknown_entries + recovered.unknown_async_chunk_keys;
    push_registration(accumulator, registration);
}

/// `inspectEsbuildWrapper`: `__commonJS`/`__esm` helpers with literal
/// module tables.
pub fn inspect_esbuild_wrapper<'a>(
    cx: &AstContext<'a>,
    call: &Node<'a>,
    accumulator: &mut StaticAccumulator,
    semantics: &dyn StaticSemantics<'a>,
) {
    let source = cx.source();
    let Some(callee) = call.field(source, Field::Callee) else {
        return;
    };
    let name = callee_name(cx, callee);
    let wrapper = if name == "__commonJS" || name.ends_with(".__commonJS") {
        "commonjs"
    } else if name == "__esm" || name.ends_with(".__esm") {
        "esm"
    } else {
        return;
    };
    let Some(table) = call
        .field_list(source, Field::Arguments)
        .first()
        .copied()
        .flatten()
        .filter(|it| it.babel_type() == "ObjectExpression")
    else {
        return;
    };
    let runtime = format!("esbuild-{wrapper}");
    let recovered = recover_bundler_modules(cx, &table, accumulator, &runtime, semantics);
    if recovered.modules.is_empty() {
        return;
    }
    accumulator.unknown_findings += recovered.unknown_async_chunk_keys;
    let registration = BundlerRegistration {
        bundler: Bundler::Esbuild,
        runtime,
        chunk_keys: vec![format!("{wrapper}@{}", cx.start(call))],
        unknown_chunk_keys: 0,
        runtime_require_name: None,
        runtime_module_cache_status: RuntimeModuleCacheStatus::NotObserved,
        entry_module_keys: Vec::new(),
        unknown_entry_module_keys: 0,
        async_chunk_keys: recovered.async_chunk_keys,
        unknown_async_chunk_keys: recovered.unknown_async_chunk_keys,
        modules: sorted_modules(recovered.modules),
        location: range(cx, call),
    };
    push_registration(accumulator, registration);
}

fn recover_bundler_modules<'a>(
    cx: &AstContext<'a>,
    table: &Node<'a>,
    accumulator: &mut StaticAccumulator,
    runtime: &str,
    semantics: &dyn StaticSemantics<'a>,
) -> Recovered {
    let mut recovered = Recovered {
        modules: Vec::new(),
        async_chunk_keys: Vec::new(),
        unknown_async_chunk_keys: 0,
    };
    for property in table
        .field_list(cx.source(), Field::Properties)
        .into_iter()
        .flatten()
    {
        let Some((module, asynchronous)) =
            recover_bundler_module(cx, &property, accumulator, runtime, semantics)
        else {
            continue;
        };
        recovered.modules.push(module);
        recovered.async_chunk_keys.extend(asynchronous.values);
        recovered.unknown_async_chunk_keys += asynchronous.unknown;
    }
    recovered
}

fn recover_bundler_module<'a>(
    cx: &AstContext<'a>,
    property: &Node<'a>,
    accumulator: &mut StaticAccumulator,
    runtime: &str,
    semantics: &dyn StaticSemantics<'a>,
) -> Option<(BundlerModule, StaticValues)> {
    let source = cx.source();
    let factory = module_factory(cx, property)?;
    let key = module_property_name(cx, property);
    if key.starts_with("[computed@") || key.starts_with("[unknown@") {
        accumulator.unknown_findings += 1;
    }
    let fingerprint = fingerprint_javascript_ast(source, factory);
    let exports = collect_javascript_exports(source, factory, Some(semantics));
    let require_name = factory_require_name(cx, &factory).map(str::to_owned);
    let require_binding_id = runtime_function_parameters(source, &factory)
        .get(2)
        .filter(|parameter| parameter.babel_type() == "Identifier")
        .and_then(|parameter| semantics.binding_id(parameter))
        .map(str::to_owned);
    if let Some(id) = &require_binding_id {
        accumulator.factory_require_binding_ids.insert(id.clone());
    }
    let asynchronous = match &require_binding_id {
        None => StaticValues {
            values: Vec::new(),
            unknown: 0,
        },
        Some(id) => {
            collect_bundler_call_argument_values(source, &factory, id, semantics, Some("e"))
        }
    };
    accumulator.module_range_index.add(ModuleRange {
        start: i64::from(cx.start(&factory)),
        end: i64::from(cx.end(&factory)),
        key: key.clone(),
        runtime: runtime.to_owned(),
        require_name: require_name.clone(),
    });
    Some((
        BundlerModule {
            module_key: key,
            factory_require_name: require_name,
            source_sha256: sha256_text(source_slice(cx, &factory)),
            structural_fingerprint_sha256: fingerprint,
            structural_fingerprint_algorithm: JAVASCRIPT_AST_FINGERPRINT_ALGORITHM.to_owned(),
            exports,
            location: range(cx, &factory),
        },
        asynchronous,
    ))
}

fn runtime_metadata<'a>(
    cx: &AstContext<'a>,
    node: Option<Node<'a>>,
    semantics: &dyn StaticSemantics<'a>,
    accumulator: &mut StaticAccumulator,
) -> RuntimeMetadata {
    let source = cx.source();
    let Some(node) = node.filter(is_bundler_function) else {
        return RuntimeMetadata {
            require_name: None,
            entry_module_keys: Vec::new(),
            unknown_entry_module_keys: u64::from(node.is_some()),
            async_chunk_keys: Vec::new(),
            unknown_async_chunk_keys: 0,
        };
    };
    let parameter = runtime_function_parameters(source, &node)
        .first()
        .copied()
        .filter(|parameter| parameter.babel_type() == "Identifier");
    let require_name = parameter
        .and_then(|parameter| parameter.identifier_name())
        .map(str::to_owned);
    let require_binding_id = parameter
        .and_then(|parameter| semantics.binding_id(&parameter))
        .map(str::to_owned);
    if let Some(id) = &require_binding_id {
        accumulator.factory_require_binding_ids.insert(id.clone());
    }
    if require_name.is_none() {
        return RuntimeMetadata {
            require_name,
            entry_module_keys: Vec::new(),
            unknown_entry_module_keys: 1,
            async_chunk_keys: Vec::new(),
            unknown_async_chunk_keys: 0,
        };
    }
    let (entries, asynchronous) = match &require_binding_id {
        None => (
            StaticValues {
                values: Vec::new(),
                unknown: 0,
            },
            StaticValues {
                values: Vec::new(),
                unknown: 0,
            },
        ),
        Some(id) => (
            collect_bundler_call_argument_values(source, &node, id, semantics, None),
            collect_bundler_call_argument_values(source, &node, id, semantics, Some("e")),
        ),
    };
    RuntimeMetadata {
        require_name,
        entry_module_keys: entries.values,
        unknown_entry_module_keys: entries.unknown,
        async_chunk_keys: asynchronous.values,
        unknown_async_chunk_keys: asynchronous.unknown,
    }
}

/// `collectBundlerCallArgumentValues`: the first literal argument of every
/// loader (or loader-member) call inside `factory`.
fn collect_bundler_call_argument_values<'a>(
    source: &'a str,
    factory: &Node<'a>,
    binding_id: &str,
    semantics: &dyn StaticSemantics<'a>,
    member: Option<&str>,
) -> StaticValues {
    struct Collect<'s, 'a> {
        source: &'a str,
        semantics: &'s dyn StaticSemantics<'a>,
        ids: HashSet<String>,
        member: Option<&'s str>,
        values: Vec<String>,
        unknown: u64,
    }
    impl<'a> AstVisitor<'a> for Collect<'_, 'a> {
        fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, _: &[Node<'a>]) {
            if !matches!(node.babel_type(), "CallExpression" | "NewExpression") {
                return;
            }
            match factory_loader_member_at(
                self.source,
                node,
                self.semantics,
                &self.ids,
                self.member,
            ) {
                None => {}
                Some(RequireLoaderFact::Unknown) => self.unknown += 1,
                Some(RequireLoaderFact::FactoryLoader) => {
                    let first = node
                        .field_list(self.source, Field::Arguments)
                        .first()
                        .copied()
                        .flatten();
                    match argument_value(self.source, first) {
                        Some(value) => self.values.push(value.into_owned()),
                        None => self.unknown += 1,
                    }
                }
            }
        }
    }
    let mut collect = Collect {
        source,
        semantics,
        ids: HashSet::from([binding_id.to_owned()]),
        member,
        values: Vec::new(),
        unknown: 0,
    };
    let _: ControlFlow<()> = traverse(*factory, source, &mut collect, || ControlFlow::Continue(()));
    unique_values(collect.values, collect.unknown)
}
