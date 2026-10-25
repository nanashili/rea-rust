//! Conservative provenance paths for Electron bridge wrappers.
//!
//! The direct Electron inspectors intentionally report syntax facts.  This
//! pass adds the interprocedural edge that matters for a preload bridge: an
//! exposed object member whose function reaches an IPC endpoint.  It only
//! emits paths when both the exposure object and the endpoint identity are
//! statically proven.

use std::collections::HashMap;

use super::symbolic_reads::collect_symbolic_read_uncertainty;
use crate::javascript::ast::{AstContext, AstVisitor, Field, Node, traverse};
use crate::javascript::contracts::static_analysis::{CallPath, CallPathStep};
use crate::javascript::semantic::ast_values::{is_class, is_function, property_key_of, unwrapped};
use crate::javascript::semantic::state::SemanticState;
use crate::javascript::semantic::value_types::{JsString, Primitive};

use super::electron_context_bridge::{exposure_arguments, members_for_exposure};
use super::electron_ipc::{IpcMode, channel_value, ipc_descriptor};
use super::electron_values::{electron_callee_path, electron_static_value, member_path};
use super::helpers::range;
use super::parents::ParentMap;

pub struct WrappedElectronAnalysis {
    pub paths: Vec<CallPath>,
    pub context_bridge_replacements:
        Vec<crate::javascript::contracts::static_analysis::SourcePoint>,
}

pub fn collect_electron_wrapped_call_paths<'a>(
    context: &AstContext<'a>,
    nodes: &[Node<'a>],
    exports: &HashMap<u32, Vec<String>>,
    state: &SemanticState<'a>,
    unknown_findings: &mut u64,
) -> WrappedElectronAnalysis {
    let mut paths = Vec::new();
    let mut context_bridge_replacements = Vec::new();
    let parents = ParentMap::new(context);

    if collect_symbolic_read_uncertainty(context, nodes, state) {
        *unknown_findings = (*unknown_findings).saturating_add(1);
    }

    for exposure in nodes.iter().copied().filter(|node| {
        if !matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression"
        ) {
            return false;
        }
        let Some(callee) = node.field(context.source(), Field::Callee) else {
            return false;
        };
        let Some(path) = electron_callee_path(context, callee, exports) else {
            return false;
        };
        path.first().is_some_and(|root| root == "contextBridge")
            && !runtime_import_root(context, state, callee)
            && matches!(
                path.get(1).map(String::as_str),
                Some("exposeInMainWorld" | "exposeInIsolatedWorld")
            )
    }) {
        let Some(callee) = exposure.field(context.source(), Field::Callee) else {
            continue;
        };
        let Some(method) =
            electron_callee_path(context, callee, exports).and_then(|path| path.get(1).cloned())
        else {
            continue;
        };
        let Some(arguments) = exposure_arguments(context, &method, exposure) else {
            continue;
        };
        if arguments
            .world_id
            .as_ref()
            .is_some_and(|world_id| world_id.status != "literal")
        {
            *unknown_findings = (*unknown_findings).saturating_add(1);
        }
        let Some(api_key) = arguments.api_key.and_then(|node| {
            let value = electron_static_value(context, Some(node));
            (value.status == "literal").then(|| match value.value {
                Primitive::String(value) => value,
                _ => JsString::new_const(),
            })
        }) else {
            *unknown_findings = (*unknown_findings).saturating_add(1);
            continue;
        };
        let Some(api_object) = arguments.api else {
            *unknown_findings = (*unknown_findings).saturating_add(1);
            continue;
        };
        let api_object = unwrapped(context.source(), api_object);
        if api_object.babel_type() != "ObjectExpression" {
            continue;
        }

        let (api_status, _, unknown_members) = members_for_exposure(context, Some(api_object));
        let guarded = has_guarded_ancestor(&parents, exposure)
            || contains_guard_expression(context, exposure)
            || has_sequential_fallthrough_guard(context, &parents, exposure);
        if !guarded
            && arguments
                .world_id
                .as_ref()
                .is_none_or(|world_id| world_id.status == "literal")
            && (api_status != "object-literal" || unknown_members > 0)
        {
            context_bridge_replacements.push(range(context, &exposure).start);
        }

        collect_api_member_paths(
            context,
            api_object,
            exposure,
            api_key,
            &[],
            exports,
            state,
            &mut paths,
        );
    }

    paths.sort_by_key(|path| {
        (
            path.steps
                .first()
                .map(|step| (step.location.start.line, step.location.start.column)),
            path.steps
                .last()
                .map(|step| (step.location.start.line, step.location.start.column)),
        )
    });
    paths.dedup();
    WrappedElectronAnalysis {
        paths,
        context_bridge_replacements,
    }
}

fn has_guarded_ancestor<'a>(parents: &ParentMap<'a>, node: Node<'a>) -> bool {
    let mut current = node;
    while let Some(parent) = parents.parent(&current) {
        if matches!(
            parent.babel_type(),
            "IfStatement"
                | "ConditionalExpression"
                | "LogicalExpression"
                | "SwitchCase"
                | "ForStatement"
                | "ForInStatement"
                | "ForOfStatement"
                | "WhileStatement"
                | "DoWhileStatement"
                | "CatchClause"
        ) {
            return true;
        }
        current = parent;
    }
    false
}

fn contains_guard_expression(context: &AstContext<'_>, node: Node<'_>) -> bool {
    if matches!(
        node.babel_type(),
        "ConditionalExpression" | "LogicalExpression"
    ) {
        return true;
    }
    context
        .children(&node)
        .into_iter()
        .any(|child| contains_guard_expression(context, child))
}

fn has_sequential_fallthrough_guard<'a>(
    context: &AstContext<'a>,
    parents: &ParentMap<'a>,
    node: Node<'a>,
) -> bool {
    let mut child = node;
    let mut parent = parents.parent(&child);

    while let Some(current) = parent {
        if current.babel_type() == "BlockStatement" {
            let statements: Vec<Node<'a>> = current
                .field_list(context.source(), Field::Body)
                .into_iter()
                .flatten()
                .collect();
            let Some(index) = statements
                .iter()
                .position(|statement| statement.key() == child.key())
            else {
                return false;
            };

            return statements[..index].iter().any(|statement| {
                statement.babel_type() == "IfStatement"
                    && (crate::javascript::semantic::control_flow::definite_exit(
                        context.source(),
                        statement.field(context.source(), Field::Consequent),
                    ) || crate::javascript::semantic::control_flow::definite_exit(
                        context.source(),
                        statement.field(context.source(), Field::Alternate),
                    ))
            });
        }

        child = current;
        parent = parents.parent(&child);
    }

    false
}

/// Walk the exposed object using the same bounded member expansion as the
/// symbolic TypeScript collector.  An exposed member may itself be a literal
/// object, so inspecting only the first property level loses paths such as
/// `reaApi.nested.write` even though the terminal IPC call is statically
/// proven.
fn collect_api_member_paths<'a>(
    context: &AstContext<'a>,
    object: Node<'a>,
    exposure: Node<'a>,
    api_key: JsString,
    prefix: &[JsString],
    exports: &HashMap<u32, Vec<String>>,
    state: &SemanticState<'a>,
    paths: &mut Vec<CallPath>,
) {
    for property in object
        .field_list(context.source(), Field::Properties)
        .into_iter()
        .flatten()
    {
        let Some(member) = property_key_of(context.source(), &property) else {
            continue;
        };

        let mut member_path = prefix.to_vec();
        member_path.push(member.clone());

        if let Some(function) = function_value(context, property) {
            collect_function_paths(
                context,
                function,
                exposure,
                api_key.clone(),
                member_path,
                exports,
                state,
                paths,
            );
            continue;
        }

        let Some(value) = property.field(context.source(), Field::Value) else {
            continue;
        };
        let value = unwrapped(context.source(), value);
        if value.babel_type() == "ObjectExpression" {
            collect_api_member_paths(
                context,
                value,
                exposure,
                api_key.clone(),
                &member_path,
                exports,
                state,
                paths,
            );
        }
    }
}

fn function_value<'a>(context: &AstContext<'a>, property: Node<'a>) -> Option<Node<'a>> {
    if property.babel_type() == "ObjectMethod" {
        return Some(property);
    }
    let value = property.field(context.source(), Field::Value)?;
    matches!(
        value.babel_type(),
        "FunctionExpression" | "ArrowFunctionExpression"
    )
    .then_some(value)
}

fn collect_function_paths<'context, 'ast, 'state>(
    context: &'context AstContext<'ast>,
    function: Node<'ast>,
    exposure: Node<'ast>,
    api_key: JsString,
    member_path: Vec<JsString>,
    exports: &'context HashMap<u32, Vec<String>>,
    state: &'state SemanticState<'ast>,
    paths: &mut Vec<CallPath>,
) {
    let mut visitor = PathVisitor {
        context,
        exposure,
        api_key,
        member_path,
        exports,
        state,
        function,
        paths,
    };
    let _ = traverse(function, context.source(), &mut visitor, || {
        std::ops::ControlFlow::<()>::Continue(())
    });
}

struct PathVisitor<'context, 'ast, 'state> {
    context: &'context AstContext<'ast>,
    exposure: Node<'ast>,
    api_key: JsString,
    member_path: Vec<JsString>,
    exports: &'context HashMap<u32, Vec<String>>,
    state: &'state SemanticState<'ast>,
    function: Node<'ast>,
    paths: &'context mut Vec<CallPath>,
}

impl<'ast> AstVisitor<'ast> for PathVisitor<'_, 'ast, '_> {
    fn skip(&mut self, node: &Node<'ast>) -> bool {
        if node.key() == self.function.key() {
            return false;
        }

        is_function(node) || is_class(node)
    }

    fn enter(
        &mut self,
        node: &Node<'ast>,
        _parent: Option<&Node<'ast>>,
        _ancestors: &[Node<'ast>],
    ) {
        if !matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression"
        ) {
            return;
        }
        let Some(callee) = node.field(self.context.source(), Field::Callee) else {
            return;
        };
        let path = electron_callee_path(self.context, callee, self.exports);
        if path.is_some() && runtime_import_root(self.context, self.state, callee) {
            return;
        }
        let terminal_path = path.clone().or_else(|| member_path(self.context, callee));
        let Some(terminal_path) = terminal_path else {
            return;
        };
        let is_electron_ipc = path.as_ref().is_some_and(|path| {
            ipc_descriptor(path).is_some_and(|descriptor| {
                matches!(descriptor.mode, IpcMode::Send | IpcMode::Invoke)
            })
        });
        let is_clipboard = terminal_path == ["navigator", "clipboard", "writeText"];
        let is_sender = terminal_path
            .first()
            .is_some_and(|segment| segment == "ipc-event")
            && terminal_path
                .get(1)
                .is_some_and(|segment| segment == "sender");
        if !is_electron_ipc && !is_clipboard && !is_sender {
            return;
        }
        let channel = is_electron_ipc
            .then(|| channel_value(self.context, *node).0)
            .flatten();
        let terminal_label = if is_electron_ipc
            && terminal_path
                .first()
                .map_or(true, |segment| segment != "electron")
        {
            format!("electron.{}", terminal_path.join("."))
        } else {
            terminal_path.join(".")
        };
        let entry_path = std::iter::once(self.api_key.clone())
            .chain(self.member_path.iter().cloned().map(JsString::from))
            .collect::<Vec<_>>();
        let entry = JsString::join(entry_path.iter().cloned(), ".");
        let steps = vec![
            CallPathStep {
                kind: "exposure".to_owned(),
                label: entry.to_string(),
                location: range(self.context, &self.exposure),
                module_key: None,
                module_runtime: None,
            },
            CallPathStep {
                kind: "function".to_owned(),
                label: function_label(self.context, self.function),
                location: range(self.context, &self.function),
                module_key: None,
                module_runtime: None,
            },
            CallPathStep {
                kind: "terminal".to_owned(),
                label: terminal_label.clone(),
                location: range(self.context, node),
                module_key: None,
                module_runtime: None,
            },
        ];
        self.paths.push(CallPath {
            entry_kind: "bridge-member".to_owned(),
            entry,
            entry_path: Some(entry_path),
            channel,
            terminal: terminal_label,
            resolution: "candidate".to_owned(),
            steps,
            conditions: Vec::new(),
        });
    }
}

/// Wrapped-call paths are a CommonJS substitution boundary.  The TypeScript
/// symbolic collector intentionally leaves ESM import bindings unresolved at
/// this boundary, even though direct Electron inspectors still report them.
/// Keep the path producer from turning those direct identities into bridge
/// candidates.
fn runtime_import_root<'a>(
    context: &AstContext<'a>,
    state: &SemanticState<'a>,
    callee: Node<'a>,
) -> bool {
    let mut root = callee;
    while matches!(
        root.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    ) {
        let Some(object) = root.field(context.source(), Field::Object) else {
            return false;
        };
        root = object;
    }
    let Some(name) = root.identifier_name() else {
        return false;
    };
    let Some(binding) = state.resolve_binding(&root, name) else {
        return false;
    };
    state.binding(binding).runtime_import
}

fn function_label(context: &AstContext<'_>, function: Node<'_>) -> String {
    function
        .field(context.source(), Field::Id)
        .and_then(|id| id.identifier_name())
        .map(str::to_owned)
        .unwrap_or_else(|| "closure".to_owned())
}
