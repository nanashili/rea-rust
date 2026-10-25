//! Return-site collection and bounded return-value projection.
//!
//! This module owns the source-order parts of `javascriptSemanticReturns.ts`.
//! Value interpretation is deliberately supplied by the caller: the return
//! pass must not manufacture a literal or provenance result when the value
//! producer has not established one yet.

use serde::Serialize;
use std::collections::HashSet;

use crate::javascript::ast::Node;
use crate::javascript::contracts::semantic_ir::SemanticModuleLink;
use crate::javascript::parser::SourceRange;
use crate::javascript::resolution::mode::ModuleResolutionMode;

use super::call_resolution::{
    LocalCallableResolution, callable_nodes, resolve_local_callable_binding,
    resolve_local_callables,
};
use super::callable_results::{CallableResultKind, callable_result_expressions};
use super::coverage::SemanticReturnCoverage;
use super::module_links::CollectedModuleLinks;
use super::projection::SemanticCallable;
use super::provenance::BindingProvenance;
use super::state::SemanticState;
use super::value_types::{Coverage, JsString, Primitive, SemanticValue, SlotPresence};
use super::values::{evaluate_semantic_expression, evaluate_semantic_provenance};

/// A return site with its source range and caller-owned value interpretation.
#[derive(Clone, Debug)]
pub struct SemanticReturnSite<'a> {
    pub return_site_id: String,
    pub location: SourceRange,
    pub identity_reference_location: Option<SourceRange>,
    pub value: SemanticValue,
    pub node: Option<Node<'a>>,
}

/// Return data for one admitted callable.
#[derive(Clone, Debug)]
pub struct SemanticCallableReturns<'a> {
    pub callable: SemanticCallable,
    pub return_sites: Vec<SemanticReturnSite<'a>>,
    pub return_coverage: SemanticReturnCoverage,
}

impl<'a> SemanticCallableReturns<'a> {
    /// Consume the internal projection into the provider-neutral IR contract.
    ///
    /// The value is moved through unchanged so the contract retains the
    /// value evaluator's typed representation and provenance-bearing reason.
    pub fn into_contract(self) -> crate::javascript::contracts::semantic_ir::SemanticCallable {
        let return_sites = self
            .return_sites
            .into_iter()
            .map(
                |site| crate::javascript::contracts::semantic_ir::SemanticReturnSite {
                    return_site_id: site.return_site_id,
                    location: site.location.into(),
                    identity_reference_location: site.identity_reference_location.map(Into::into),
                    value: site.value,
                },
            )
            .collect();

        crate::javascript::contracts::semantic_ir::SemanticCallable {
            callable_id: self.callable.callable_id,
            kind: self.callable.kind,
            name: self.callable.name,
            container_scope_id: self.callable.container_scope_id,
            body_scope_id: self.callable.body_scope_id,
            location: self.callable.location.into(),
            return_sites,
            return_coverage: serde_json::to_value(self.return_coverage)
                .expect("semantic return coverage is serializable"),
        }
    }
}

impl<'a> From<SemanticCallableReturns<'a>>
    for crate::javascript::contracts::semantic_ir::SemanticCallable
{
    fn from(value: SemanticCallableReturns<'a>) -> Self {
        value.into_contract()
    }
}

/// Collect direct returns while excluding nested functions and classes.
///
/// `evaluate` is the value producer owned by the semantic-value pass. A
/// missing expression is represented by the same unknown value as TypeScript;
/// no syntax-only literal inference is performed here.
pub fn collect_semantic_returns<'a, F>(
    state: &SemanticState<'a>,
    callables: &[SemanticCallable],
    parser_partial: bool,
    mut evaluate: F,
) -> Vec<SemanticCallableReturns<'a>>
where
    F: FnMut(Node<'a>) -> SemanticValue,
{
    callables
        .iter()
        .map(|callable| {
            let Some(node) = callable_node(state, callable) else {
                return SemanticCallableReturns {
                    callable: callable.clone(),
                    return_sites: Vec::new(),
                    return_coverage: SemanticReturnCoverage {
                        status: super::coverage::SemanticReturnCoverageStatus::Partial,
                        retained_count: 0,
                        omitted_count: None,
                    },
                };
            };

            let return_sites =
                callable_result_expressions(state.source, &node)
                    .into_iter()
                    .filter(|result| result.kind == CallableResultKind::Return)
                    .map(|result| {
                        let value = result.node.map(&mut evaluate).unwrap_or_else(|| {
                            SemanticValue::Unknown {
                                reason: "Return has no value.".into(),
                                resource_limit: None,
                            }
                        });
                        SemanticReturnSite {
                            return_site_id: return_site_id(
                                &callable.callable_id,
                                state.context.range(&result.site),
                            ),
                            location: state.context.range(&result.site),
                            identity_reference_location: result
                                .node
                                .filter(|node| node.babel_type() == "Identifier")
                                .map(|node| state.context.range(&node)),
                            value,
                            node: result.node,
                        }
                    })
                    .collect::<Vec<_>>();

            SemanticCallableReturns {
                callable: callable.clone(),
                return_coverage: SemanticReturnCoverage::new(return_sites.len(), parser_partial),
                return_sites,
            }
        })
        .collect()
}

/// Collect returns with the native bounded value producer.
pub fn collect_semantic_returns_with_values<'a>(
    state: &SemanticState<'a>,
    callables: &[SemanticCallable],
    parser_partial: bool,
) -> Vec<SemanticCallableReturns<'a>> {
    collect_semantic_returns(state, callables, parser_partial, |node| {
        evaluate_semantic_expression(node, state, None)
    })
}

/// Finalize module links after the owning binding/module pass has resolved a
/// link's lexical callable candidates. `Some` means the owning resolver had a
/// captured/default expression to evaluate and supplies zero, one, or many
/// candidates. `None` means that no captured expression was available; in
/// that case the link's already-admitted callable identity is preserved when
/// the TypeScript owner would retain it as a fallback. Ambiguous candidates
/// remain `null`, preserving the TypeScript fail-closed rule.
#[derive(Clone, Debug, Default)]
pub struct SemanticModuleCallableResolution {
    pub candidates: Option<Vec<String>>,
    pub resolution_mode: Option<ModuleResolutionMode>,
}

pub fn resolve_semantic_module_callables<F>(
    links: &[SemanticModuleLink],
    admitted_callable_ids: &HashSet<String>,
    mut resolve: F,
) -> Vec<SemanticModuleLink>
where
    F: FnMut(&SemanticModuleLink) -> SemanticModuleCallableResolution,
{
    links
        .iter()
        .cloned()
        .map(|mut link| {
            if link.kind == "type-import" {
                link.callable_id = None;
                return link;
            }
            let resolution = resolve(&link);
            if let Some(resolution_mode) = resolution.resolution_mode {
                link.resolution_mode = Some(resolution_mode);
            }

            let Some(resolved_candidates) = resolution.candidates else {
                if link.local_name.is_none()
                    && link
                        .callable_id
                        .as_ref()
                        .is_some_and(|id| admitted_callable_ids.contains(id))
                {
                    return link;
                }

                link.callable_id = None;
                return link;
            };

            let mut candidates = resolved_candidates
                .into_iter()
                .filter(|candidate| admitted_callable_ids.contains(candidate));
            let first = candidates.next();
            link.callable_id = match (first, candidates.next()) {
                (Some(candidate), None) => Some(candidate),
                _ => None,
            };
            link
        })
        .collect()
}

/// Resolve module links through the binding and default-expression facts
/// retained by the module-link producer. This keeps module exports on the
/// same lexical callable resolver as local call sites.
pub fn resolve_semantic_module_callables_from_state<'a>(
    state: &SemanticState<'a>,
    links: &CollectedModuleLinks<'a>,
    admitted_callable_ids: &HashSet<String>,
) -> Vec<SemanticModuleLink> {
    let callable_nodes = callable_nodes(state);
    let mut cache = std::collections::HashMap::new();

    links
        .links
        .iter()
        .cloned()
        .zip(
            links
                .link_bindings
                .iter()
                .zip(&links.default_export_expressions),
        )
        .map(|(mut link, (binding, default_expression))| {
            if link.kind == "type-import" {
                link.callable_id = None;
                return link;
            }
            let pre_resolved_callable_id = link.callable_id.clone();

            let resolution = if let Some(expression) = default_expression {
                resolve_local_callables(
                    *expression,
                    state,
                    &callable_nodes,
                    &HashSet::new(),
                    &mut cache,
                )
            } else if let Some(binding) = binding {
                resolve_local_callable_binding(*binding, state, &callable_nodes, &mut cache)
            } else {
                LocalCallableResolution {
                    callable_ids: Vec::new(),
                    complete: false,
                    reason: "Module link has no lexical binding or default expression.".to_owned(),
                    cycle_dependent: false,
                }
            };

            let mut candidates = resolution
                .callable_ids
                .into_iter()
                .filter(|id| admitted_callable_ids.contains(id));
            link.callable_id = match (candidates.next(), candidates.next()) {
                (Some(id), None) if resolution.complete => Some(id),
                _ => None,
            };
            if link.specifier.is_none()
                && let Some(binding) = binding
                && let BindingProvenance::Module { origins } =
                    evaluate_semantic_provenance(state.binding(*binding), state)
                && let Some(origin) = origins.first()
            {
                link.resolution_mode = origin.resolution_mode.map(|mode| match mode {
                    super::state::ResolutionMode::Import => ModuleResolutionMode::Import,
                    super::state::ResolutionMode::Require => ModuleResolutionMode::Require,
                    super::state::ResolutionMode::CompilerDependent => {
                        ModuleResolutionMode::CompilerDependent
                    }
                });
            }
            if binding.is_none()
                && default_expression.is_none()
                && link.local_name.is_none()
                && pre_resolved_callable_id
                    .as_ref()
                    .is_some_and(|id| admitted_callable_ids.contains(id))
            {
                link.callable_id = pre_resolved_callable_id;
                return link;
            }
            link
        })
        .collect()
}

fn callable_node<'a>(state: &SemanticState<'a>, callable: &SemanticCallable) -> Option<Node<'a>> {
    let start = callable.location.start.offset;
    let end = callable.location.end.offset;
    find_callable_node(
        state,
        state.program,
        callable.callable_id.as_str(),
        start,
        end,
    )
}

fn find_callable_node<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    callable_id: &str,
    start: u32,
    end: u32,
) -> Option<Node<'a>> {
    if state.context.start(&node) == start
        && state.context.end(&node) == end
        && super::projection::callable_id_for_node(&state.context, &node).as_deref()
            == Some(callable_id)
    {
        return Some(node);
    }
    node.children(state.source)
        .into_iter()
        .find_map(|child| find_callable_node(state, child, callable_id, start, end))
}

fn return_site_id(callable_id: &str, location: SourceRange) -> String {
    format!(
        "{callable_id}:return:{}:{}:{}:{}",
        location.start.line, location.start.column, location.end.line, location.end.column
    )
}

/// A JSON-pointer leaf in a projected return value.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProjectedReturnField {
    pub path: JsString,
    pub presence: SlotPresence,
    pub state: ProjectedFieldState,
    pub value: Option<ProjectedReturnValue>,
    pub reason: Option<JsString>,
}

/// A JSON-compatible primitive projection that keeps JavaScript strings in
/// their owning UTF-16 representation until serialization.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ProjectedReturnValue {
    Literal(Primitive),
    Union(Vec<Primitive>),
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectedFieldState {
    Literal,
    Union,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProjectedPropertyCoverage {
    pub path: JsString,
    pub status: ProjectedCoverageStatus,
    pub omitted: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectedCoverageStatus {
    Complete,
    Partial,
}

/// Flatten a semantic value into bounded pointer leaves, preserving slot
/// presence and the owning container's coverage at each object/array node.
pub fn flatten_semantic_return_value(
    value: &SemanticValue,
) -> (Vec<ProjectedReturnField>, Vec<ProjectedPropertyCoverage>) {
    let mut fields = Vec::new();
    let mut coverage = Vec::new();
    flatten_value(
        value,
        &JsString::from(""),
        SlotPresence::Present,
        &mut fields,
        &mut coverage,
    );
    fields.sort_by(|left, right| left.path.compare_code_points(&right.path));
    coverage.sort_by(|left, right| left.path.compare_code_points(&right.path));
    (fields, coverage)
}

fn flatten_value(
    value: &SemanticValue,
    path: &JsString,
    presence: SlotPresence,
    fields: &mut Vec<ProjectedReturnField>,
    coverage: &mut Vec<ProjectedPropertyCoverage>,
) {
    if presence != SlotPresence::Present {
        fields.push(ProjectedReturnField {
            path: path.clone(),
            presence,
            state: ProjectedFieldState::Unknown,
            value: None,
            reason: semantic_reason(value),
        });
        return;
    }

    match value {
        SemanticValue::Literal { value } => fields.push(ProjectedReturnField {
            path: path.clone(),
            presence,
            state: ProjectedFieldState::Literal,
            value: Some(ProjectedReturnValue::Literal(value.clone())),
            reason: None,
        }),
        SemanticValue::Union { values } => fields.push(ProjectedReturnField {
            path: path.clone(),
            presence,
            state: ProjectedFieldState::Union,
            value: Some(ProjectedReturnValue::Union(values.clone())),
            reason: None,
        }),
        SemanticValue::Unknown { .. }
        | SemanticValue::Ambiguous { .. }
        | SemanticValue::Cycle { .. } => fields.push(ProjectedReturnField {
            path: path.clone(),
            presence,
            state: ProjectedFieldState::Unknown,
            value: None,
            reason: semantic_reason(value),
        }),
        SemanticValue::Object {
            properties,
            coverage: value_coverage,
        }
        | SemanticValue::Array {
            items: properties,
            coverage: value_coverage,
        } => {
            let (status, omitted) = match value_coverage {
                Coverage::Exact => (ProjectedCoverageStatus::Complete, Some(0)),
                Coverage::Unknown { omitted } => (ProjectedCoverageStatus::Partial, *omitted),
            };
            coverage.push(ProjectedPropertyCoverage {
                path: path.to_owned(),
                status,
                omitted,
            });
            for property in properties {
                flatten_value(
                    &property.value,
                    &path.concat(&property_pointer(&property.name)),
                    property.presence,
                    fields,
                    coverage,
                );
            }
        }
    }
}

fn semantic_reason(value: &SemanticValue) -> Option<JsString> {
    match value {
        SemanticValue::Unknown { reason, .. }
        | SemanticValue::Ambiguous { reason, .. }
        | SemanticValue::Cycle { reason, .. } => Some(reason.clone()),
        _ => Some("Property presence is uncertain.".into()),
    }
}

fn property_pointer(name: &JsString) -> JsString {
    let mut units = Vec::with_capacity(name.len() + 1);
    units.push(b'/' as u16);

    for unit in name.units() {
        match *unit {
            0x007e => units.extend_from_slice(&[b'~' as u16, b'0' as u16]),
            0x002f => units.extend_from_slice(&[b'~' as u16, b'1' as u16]),
            unit => units.push(unit),
        }
    }

    JsString::from_utf16(units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::ControlFlow;

    use oxc_allocator::Allocator;

    use crate::javascript::ast::AstContext;
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::definitions::collect_definitions;
    use crate::javascript::semantic::projection::collect_semantic_projection;
    use crate::javascript::semantic::state::ResolutionMode;
    use crate::javascript::semantic::value_types::{JsString, Property};

    #[test]
    fn flatten_escapes_pointers_and_retains_container_coverage() {
        let value = SemanticValue::Object {
            properties: vec![Property {
                name: "a/b~c".into(),
                value: SemanticValue::Literal {
                    value: Primitive::String("ok".to_owned().into()),
                },
                presence: SlotPresence::Present,
            }],
            coverage: Coverage::Exact,
        };
        let (fields, coverage) = flatten_semantic_return_value(&value);
        assert_eq!(coverage[0].path, "");
        assert_eq!(coverage[0].omitted, Some(0));
        assert_eq!(fields[0].path, "/a~1b~0c");
    }

    #[test]
    fn flatten_unknown_presence_does_not_claim_the_value() {
        let value = SemanticValue::Object {
            properties: vec![Property {
                name: "maybe".into(),
                value: SemanticValue::Literal {
                    value: Primitive::Boolean(true),
                },
                presence: SlotPresence::UnknownCoverage,
            }],
            coverage: Coverage::Unknown { omitted: None },
        };
        let (fields, _) = flatten_semantic_return_value(&value);
        assert_eq!(fields[0].presence, SlotPresence::UnknownCoverage);
        assert_eq!(fields[0].state, ProjectedFieldState::Unknown);
        assert_eq!(fields[0].value, None);
    }

    #[test]
    fn flatten_preserves_unpaired_javascript_string_units_for_json() {
        let value = SemanticValue::Literal {
            value: Primitive::String(JsString::from_utf16(vec![0xd800, b'x' as u16])),
        };

        let (fields, _) = flatten_semantic_return_value(&value);
        assert_eq!(
            fields[0].value,
            Some(ProjectedReturnValue::Literal(Primitive::String(
                JsString::from_utf16(vec![0xd800, b'x' as u16]),
            )))
        );

        let serialized = serde_json::to_string(&fields).expect("projected field is serializable");
        assert!(serialized.contains(r#"\ud800x"#));
    }

    #[test]
    fn flatten_preserves_unpaired_object_key_units_in_pointer_paths() {
        let value = SemanticValue::Object {
            properties: vec![Property {
                name: JsString::from_utf16(vec![0xd800, b'x' as u16]),
                value: SemanticValue::Literal {
                    value: Primitive::Boolean(true),
                },
                presence: SlotPresence::Present,
            }],
            coverage: Coverage::Exact,
        };

        let (fields, coverage) = flatten_semantic_return_value(&value);
        assert_eq!(fields[0].path.units(), &[b'/' as u16, 0xd800, b'x' as u16]);
        assert!(coverage[0].path.is_empty());

        let serialized = serde_json::to_string(&fields).expect("projected field is serializable");
        assert!(serialized.contains(r#"/\ud800x"#));
    }

    #[test]
    fn flatten_sorts_paths_by_javascript_code_points() {
        let value = SemanticValue::Object {
            properties: vec![
                Property {
                    name: JsString::from_utf16(vec![0xd800, 0xdc00]),
                    value: SemanticValue::Literal {
                        value: Primitive::Boolean(true),
                    },
                    presence: SlotPresence::Present,
                },
                Property {
                    name: JsString::from_utf16(vec![0xe000]),
                    value: SemanticValue::Literal {
                        value: Primitive::Boolean(false),
                    },
                    presence: SlotPresence::Present,
                },
            ],
            coverage: Coverage::Exact,
        };

        let (fields, _) = flatten_semantic_return_value(&value);
        assert_eq!(fields[0].path, "/\u{e000}");
        assert_eq!(fields[1].path, "/\u{10000}");
    }

    #[test]
    fn collect_returns_excludes_nested_callables_and_keeps_source_order() {
        let source = "function outer() { return 1; function nested() { return 2; } return 3; }";
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(&allocator, source, Some("returns.js"))
            .expect("valid fixture");
        let ControlFlow::Continue(state) = collect_definitions::<()>(
            AstContext::new(parsed.program),
            ResolutionMode::Import,
            || ControlFlow::Continue(()),
        ) else {
            panic!("fixture analysis must not cancel");
        };
        let (callables, _) = collect_semantic_projection(&state);
        let collected = collect_semantic_returns_with_values(&state, &callables, false);
        let outer = collected
            .iter()
            .find(|entry| {
                entry
                    .callable
                    .name
                    .as_ref()
                    .is_some_and(|name| name == "outer")
            })
            .expect("outer callable");
        assert_eq!(outer.return_sites.len(), 2);
        assert!(
            outer.return_sites[0].location.start.offset
                < outer.return_sites[1].location.start.offset
        );
        assert_eq!(
            outer.return_sites[0].value,
            SemanticValue::Literal {
                value: Primitive::Number(1.0),
            }
        );
        assert_eq!(
            outer.return_sites[1].value,
            SemanticValue::Literal {
                value: Primitive::Number(3.0),
            }
        );
        assert!(
            outer.return_sites[0]
                .return_site_id
                .starts_with(&format!("{}:return:", outer.callable.callable_id))
        );
    }

    #[test]
    fn module_resolution_preserves_admitted_uncaptured_fallback() {
        let location = crate::javascript::contracts::static_analysis::SourceRange {
            start: crate::javascript::contracts::static_analysis::SourcePoint {
                line: 1,
                column: 0,
            },
            end: crate::javascript::contracts::static_analysis::SourcePoint { line: 1, column: 1 },
        };
        let link = SemanticModuleLink {
            resolution_mode: Some(ModuleResolutionMode::Import),
            kind: "export-default".to_owned(),
            specifier: None,
            imported_name: None,
            local_name: None,
            exported_name: Some("default".into()),
            callable_id: Some("callable-1".to_owned()),
            location,
        };
        let admitted = HashSet::from(["callable-1".to_owned()]);

        let preserved = resolve_semantic_module_callables(&[link.clone()], &admitted, |_| {
            SemanticModuleCallableResolution {
                candidates: None,
                resolution_mode: None,
            }
        });
        assert_eq!(preserved[0].callable_id, Some("callable-1".to_owned()));

        let unresolved = resolve_semantic_module_callables(&[link], &admitted, |_| {
            SemanticModuleCallableResolution {
                candidates: Some(Vec::new()),
                resolution_mode: None,
            }
        });
        assert_eq!(unresolved[0].callable_id, None);
    }
}
