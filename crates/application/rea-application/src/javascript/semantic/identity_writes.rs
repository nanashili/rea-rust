//! Source-local object identity writes.
//!
//! This is the syntax and traversal portion of
//! `javascriptElectronMemberWrites.ts`.  Identity resolution, intrinsic
//! invocation lookup, and freshness remain explicit collaborators so this
//! module cannot silently invent runtime facts.

use std::ops::ControlFlow;

use crate::javascript::ast::{AstVisitor, Field, Node, traverse};

use super::ast_values::{
    is_member, static_property_key, unwrapped, write_site_target, write_targets,
};
use super::globals::member_path;
use super::value_types::JsString;

/// Electron's supported CommonJS module entry points.
pub fn is_electron_module(module: &str) -> bool {
    module == "electron"
        || module
            .strip_prefix("electron/")
            .is_some_and(|suffix| matches!(suffix, "common" | "main" | "renderer" | "utility"))
}

/// Remove the synthetic ES-module `default` segment from an Electron import.
pub fn electron_export_path(imported_path: &[String]) -> &[String] {
    match imported_path.first() {
        Some(segment) if segment == "default" => &imported_path[1..],
        _ => imported_path,
    }
}

/// Static identity recovery cannot establish the absence of Electron usage.
pub const ELECTRON_IDENTITY_LIMITATION: &str = "Electron API identity follows proven lexical module aliases and structurally verified module-namespace interop. Other reassignments, dynamic selections, and visibly overwritten namespace members are unresolved; missing findings do not establish absence. Arbitrary call side effects and runtime registration are not evaluated.";

/// The unwrapped root and static member keys of a member expression.
#[derive(Clone, Debug)]
pub struct ElectronMemberPath<'a> {
    pub root: Node<'a>,
    pub members: Vec<Option<JsString>>,
}

pub fn electron_member_path<'a>(source: &'a str, node: Node<'a>) -> ElectronMemberPath<'a> {
    let (root, members) = member_path(source, node);
    ElectronMemberPath { root, members }
}

/// A known intrinsic callable and its examined positional arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntrinsicInvocationKind {
    Known,
    Opaque,
}

#[derive(Clone, Debug)]
pub struct JavaScriptIntrinsicInvocation<'a> {
    pub kind: IntrinsicInvocationKind,
    /// The original bound receiver; rebinding cannot replace it.
    pub receiver: Option<Node<'a>>,
    pub path: Vec<String>,
    pub arguments: Option<Vec<Node<'a>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityWriteKind {
    Binding,
    Member,
    OpaqueCall,
}

pub type IdentityPath = Vec<Option<JsString>>;

/// Traverse identity-writing constructs with every runtime-sensitive fact
/// supplied by the caller.
pub fn collect_identity_writes_steps<'a, O, I, S, F, R, V>(
    program: Node<'a>,
    source: &'a str,
    mut origin: O,
    mut intrinsic_invocation: I,
    mut static_string: S,
    mut fresh_object: F,
    mut retain: R,
    mut observe_invocation: V,
) -> ControlFlow<()>
where
    O: FnMut(Node<'a>, IdentityWriteKind, Node<'a>) -> Vec<IdentityPath>,
    I: FnMut(Node<'a>) -> Option<JavaScriptIntrinsicInvocation<'a>>,
    S: FnMut(Option<Node<'a>>) -> Option<JsString>,
    F: FnMut(Node<'a>) -> bool,
    R: FnMut(Node<'a>, IdentityPath),
    V: FnMut(Node<'a>, Option<&JavaScriptIntrinsicInvocation<'a>>),
{
    let mut visitor = IdentityWriteVisitor {
        source,
        origin: &mut origin,
        intrinsic_invocation: &mut intrinsic_invocation,
        static_string: &mut static_string,
        fresh_object: &mut fresh_object,
        retain: &mut retain,
        observe_invocation: &mut observe_invocation,
    };

    traverse(program, source, &mut visitor, || ControlFlow::Continue(()))
}

struct IdentityWriteVisitor<'s, 'a, O, I, S, F, R, V> {
    source: &'a str,
    origin: &'s mut O,
    intrinsic_invocation: &'s mut I,
    static_string: &'s mut S,
    fresh_object: &'s mut F,
    retain: &'s mut R,
    observe_invocation: &'s mut V,
}

impl<'a, O, I, S, F, R, V> AstVisitor<'a> for IdentityWriteVisitor<'_, 'a, O, I, S, F, R, V>
where
    O: FnMut(Node<'a>, IdentityWriteKind, Node<'a>) -> Vec<IdentityPath>,
    I: FnMut(Node<'a>) -> Option<JavaScriptIntrinsicInvocation<'a>>,
    S: FnMut(Option<Node<'a>>) -> Option<JsString>,
    F: FnMut(Node<'a>) -> bool,
    R: FnMut(Node<'a>, IdentityPath),
    V: FnMut(Node<'a>, Option<&JavaScriptIntrinsicInvocation<'a>>),
{
    fn enter(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
        self.visit_invocation(*node);
        self.visit_write(*node);
    }
}

impl<'a, O, I, S, F, R, V> IdentityWriteVisitor<'_, 'a, O, I, S, F, R, V>
where
    O: FnMut(Node<'a>, IdentityWriteKind, Node<'a>) -> Vec<IdentityPath>,
    I: FnMut(Node<'a>) -> Option<JavaScriptIntrinsicInvocation<'a>>,
    S: FnMut(Option<Node<'a>>) -> Option<JsString>,
    F: FnMut(Node<'a>) -> bool,
    R: FnMut(Node<'a>, IdentityPath),
    V: FnMut(Node<'a>, Option<&JavaScriptIntrinsicInvocation<'a>>),
{
    fn visit_invocation(&mut self, node: Node<'a>) {
        let is_invocation = matches!(
            node.babel_type(),
            "CallExpression"
                | "OptionalCallExpression"
                | "NewExpression"
                | "TaggedTemplateExpression"
        );
        if !is_invocation {
            return;
        }

        let invocation = matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression"
        )
        .then(|| (self.intrinsic_invocation)(node));
        (self.observe_invocation)(node, invocation.as_ref().and_then(Option::as_ref));
        if matches!(
            node.babel_type(),
            "NewExpression" | "TaggedTemplateExpression"
        ) {
            return;
        }
        let Some(invocation) = invocation.flatten() else {
            return;
        };
        if invocation.kind == IntrinsicInvocationKind::Opaque {
            for scope in (self.origin)(node, IdentityWriteKind::OpaqueCall, node) {
                (self.retain)(node, scope);
            }
            return;
        }

        let method = invocation.path.last().map(String::as_str).unwrap_or("");
        let owner = (invocation.path.len() == 3).then(|| invocation.path[1].as_str());
        let is_mutator = (owner == Some("Object")
            && [
                "defineProperty",
                "defineProperties",
                "assign",
                "setPrototypeOf",
            ]
            .contains(&method))
            || (owner == Some("Reflect")
                && ["set", "deleteProperty", "defineProperty", "setPrototypeOf"].contains(&method));
        if !is_mutator {
            return;
        }

        let arguments = invocation.arguments.as_deref().unwrap_or(&[]);
        let targets: Vec<Option<Node<'_>>> = if owner == Some("Reflect")
            && method == "set"
            && (arguments.len() >= 4
                || arguments
                    .iter()
                    .any(|node| node.babel_type() == "SpreadElement"))
        {
            vec![arguments.first().copied(), arguments.get(3).copied()]
        } else {
            vec![arguments.first().copied()]
        };
        for target in targets {
            if target.is_none_or(|node| node.babel_type() == "SpreadElement") {
                for scope in (self.origin)(node, IdentityWriteKind::OpaqueCall, node) {
                    (self.retain)(node, scope);
                }
            }
            let Some(target) = target.filter(|node| node.babel_type() != "SpreadElement") else {
                continue;
            };
            let identities = (self.origin)(target, IdentityWriteKind::Member, node);
            if !identities.is_empty() {
                let key = if ["set", "deleteProperty", "defineProperty"].contains(&method) {
                    vec![(self.static_string)(arguments.get(1).copied())]
                } else {
                    vec![None]
                };
                for identity in identities {
                    (self.retain)(
                        node,
                        identity.into_iter().chain(key.iter().cloned()).collect(),
                    );
                }
            } else if !(self.fresh_object)(target) {
                for scope in (self.origin)(node, IdentityWriteKind::OpaqueCall, node) {
                    (self.retain)(node, scope);
                }
            }
        }
    }

    fn visit_write(&mut self, node: Node<'a>) {
        let Some(target) = write_site_target(self.source, &node) else {
            return;
        };
        for leaf in write_targets(self.source, target) {
            if leaf.babel_type() == "Identifier" {
                for identity in (self.origin)(leaf, IdentityWriteKind::Binding, node) {
                    (self.retain)(node, identity);
                }
                continue;
            }
            let member = unwrapped(self.source, leaf);
            if !is_member(&member) {
                continue;
            }
            let key = member
                .field(self.source, Field::Property)
                .and_then(|property| static_property_key(self.source, property, member.computed()));
            for identity in (self.origin)(
                member.field(self.source, Field::Object).unwrap_or(member),
                IdentityWriteKind::Member,
                node,
            ) {
                (self.retain)(node, identity.into_iter().chain([key.clone()]).collect());
            }
        }
    }
}
