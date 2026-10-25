//! Provenance evaluation for the semantic value owner.

use crate::javascript::ast::{Field, Node};

use super::super::ast_values::{read_exact_literal, static_property_key, unwrap_expression};
use super::super::opaque_effects;
use super::super::provenance::{
    BindingProvenance, semantic_ambiguous_provenance, semantic_local_provenance,
    semantic_origins_provenance, semantic_unresolved_provenance, unique_semantic_origins,
};
use super::super::require_origin::require_origin;
use super::super::state::{BindingState, DefinitionKind, ModuleOrigin, ProjectionKey};
use super::super::value_types::{JsString, ResourceLimit};
use super::{Evaluation, EvaluationPoint};

const CALLER_INDEPENDENT: isize = isize::MAX;
const EVERY_CALLER: isize = -1;

impl<'s, 'a> Evaluation<'s, 'a> {
    pub(super) fn provenance_for_binding(
        &mut self,
        binding: &BindingState<'a>,
        point: EvaluationPoint<'a>,
    ) -> BindingProvenance {
        self.record_binding_dependency(binding);
        if let Some(&head) = self.bindings.get(&binding.binding_id) {
            self.lowest = self.lowest.min(head as isize);
            return semantic_unresolved_provenance(
                "cycle",
                format!("Alias cycle at {}.", binding.name),
            );
        }

        if let Some(depths) = self.memo.provenance.get(&binding.binding_id) {
            if let Some(entry) = depths.get(&point.depth).cloned() {
                if let Some(value) = self.read_memoized(&entry) {
                    return value;
                }
            }
        }

        let position = self.bindings.len() as isize;
        let caller_dependence = self.lowest;
        self.lowest = CALLER_INDEPENDENT;
        let evaluated = self.collect_dependencies(binding, |evaluation| {
            evaluation.provenance_for_binding_uncached(binding, point)
        });
        let caller_independent = self.lowest > position;
        self.lowest = if caller_independent {
            caller_dependence
        } else {
            caller_dependence.min(self.lowest)
        };

        if caller_independent {
            self.memo
                .provenance
                .entry(binding.binding_id.clone())
                .or_default()
                .insert(point.depth, evaluated.clone());
        }
        evaluated.value
    }

    fn provenance_for_binding_uncached(
        &mut self,
        binding: &BindingState<'a>,
        point: EvaluationPoint<'a>,
    ) -> BindingProvenance {
        let provenance = self.provenance_for_binding_value(binding, point);
        let assigned = binding
            .definitions
            .iter()
            .any(|definition| definition.kind == DefinitionKind::Assignment);
        let conditionally_initialized = binding.initializers.iter().any(|initializer| {
            self.state
                .conditionally_skipped
                .contains(&initializer.node.key())
        });
        if !matches!(provenance, BindingProvenance::Module { .. })
            || (!assigned && !conditionally_initialized)
        {
            return provenance;
        }
        semantic_ambiguous_provenance(
            &provenance_origins(&provenance),
            if assigned {
                format!("Binding {} may be reassigned.", binding.name)
            } else {
                format!("Binding {} may remain uninitialized.", binding.name)
            },
        )
    }

    fn provenance_for_binding_value(
        &mut self,
        binding: &BindingState<'a>,
        point: EvaluationPoint<'a>,
    ) -> BindingProvenance {
        if matches!(
            binding.kind,
            DefinitionKind::Parameter | DefinitionKind::Catch
        ) {
            return semantic_unresolved_provenance(
                "unknown",
                if binding.kind == DefinitionKind::Parameter {
                    "Parameter provenance depends on caller arguments."
                } else {
                    "Catch binding provenance depends on the thrown value."
                },
            );
        }
        if !binding.direct_origins.is_empty() {
            let type_only = binding.kind == DefinitionKind::Import
                && !binding.runtime_import
                && binding.direct_origins.iter().all(|origin| {
                    origin.resolution_mode != Some(super::super::state::ResolutionMode::Require)
                });
            return if type_only {
                semantic_ambiguous_provenance(
                    &binding.direct_origins,
                    "A type-only import does not establish a runtime module value.",
                )
            } else {
                semantic_origins_provenance(&binding.direct_origins)
            };
        }
        let Some(initializer) = binding.initializers.first() else {
            return semantic_local_provenance();
        };
        if binding.initializers.len() > 1 {
            return semantic_ambiguous_provenance(
                &[],
                format!(
                    "Binding {} has multiple possible assignments.",
                    binding.name
                ),
            );
        }
        if initializer
            .projection
            .iter()
            .any(|key| matches!(key, ProjectionKey::Dynamic))
        {
            return semantic_unresolved_provenance("unknown", "Dynamic provenance projection.");
        }

        let binding_position = self.bindings.len();
        self.bindings
            .insert(binding.binding_id.clone(), binding_position);
        let resolved = self.provenance_for_expression(initializer.node, point.nested());
        self.bindings.remove(&binding.binding_id);
        if !matches!(resolved, BindingProvenance::Module { .. })
            || initializer.projection.is_empty()
        {
            return resolved;
        }
        let origins = provenance_origins(&resolved)
            .into_iter()
            .map(|mut origin| {
                origin
                    .imported_path
                    .extend(initializer.projection.iter().map(projection_key_string));
                origin
            })
            .collect::<Vec<_>>();
        semantic_origins_provenance(&origins)
    }

    pub(super) fn provenance_for_expression(
        &mut self,
        node: Node<'a>,
        point: EvaluationPoint<'a>,
    ) -> BindingProvenance {
        if point.depth > super::super::limits::SEMANTIC_EXPRESSION_DEPTH_LIMIT {
            self.lowest = EVERY_CALLER;
            return semantic_unresolved_provenance(
                "unknown",
                super::super::limits::resource_limit_reason(ResourceLimit::ExpressionDepth),
            );
        }
        let unwrapped_expression = unwrap_expression(self.state.source, node, false);
        if unwrapped_expression.node.key() != node.key() {
            if point.depth + unwrapped_expression.depth
                > super::super::limits::SEMANTIC_EXPRESSION_DEPTH_LIMIT
            {
                self.lowest = EVERY_CALLER;
                return semantic_unresolved_provenance(
                    "unknown",
                    super::super::limits::resource_limit_reason(ResourceLimit::ExpressionDepth),
                );
            }
            return self.provenance_for_expression(
                unwrapped_expression.node,
                EvaluationPoint {
                    depth: point.depth + unwrapped_expression.depth,
                    ..point
                },
            );
        }
        if let Some(required) = require_origin(self.state, Some(node)) {
            return semantic_origins_provenance(&[required.origin]);
        }
        if node.babel_type() == "SequenceExpression" {
            let expressions = node.field_list(self.state.source, Field::Expressions);
            return expressions
                .into_iter()
                .flatten()
                .last()
                .map(|last| self.provenance_for_expression(last, point.nested()))
                .unwrap_or_else(|| {
                    semantic_unresolved_provenance("unknown", "Empty sequence expression.")
                });
        }
        if node.babel_type() == "AssignmentExpression" && node.operator() == Some("=") {
            return node
                .field(self.state.source, Field::Right)
                .map(|right| self.provenance_for_expression(right, point.nested()))
                .unwrap_or_else(|| {
                    semantic_unresolved_provenance("unknown", "Missing assignment value.")
                });
        }
        if node.identifier_name().is_some() && node.babel_type() == "Identifier" {
            let name = node.identifier_name().expect("identifier name");
            let Some(index) = self.state.resolve_binding(&node, name) else {
                return semantic_unresolved_provenance(
                    "unknown",
                    format!("Unbound identifier {name}."),
                );
            };
            let binding = self.state.binding(index).clone();
            return self.provenance_for_binding_at_read(&binding, node, point.nested());
        }
        if matches!(
            node.babel_type(),
            "MemberExpression" | "OptionalMemberExpression"
        ) {
            let mut current = node;
            let mut members = Vec::new();
            while matches!(
                current.babel_type(),
                "MemberExpression" | "OptionalMemberExpression"
            ) {
                let Some(object) = current.field(self.state.source, Field::Object) else {
                    return semantic_unresolved_provenance("unknown", "Unsupported member base.");
                };
                let Some(property) = current.field(self.state.source, Field::Property) else {
                    return semantic_unresolved_provenance("unknown", "Dynamic provenance member.");
                };
                let Some(member) =
                    static_property_key(self.state.source, property, current.computed())
                else {
                    return semantic_unresolved_provenance("unknown", "Dynamic provenance member.");
                };
                members.push(member);
                current = object;
            }
            let base = self.provenance_for_expression(current, point.nested());
            let mut path = members;
            path.reverse();
            return append_origin_paths(base, &path);
        }
        if matches!(
            node.babel_type(),
            "ConditionalExpression" | "LogicalExpression"
        ) {
            let (left, right) = if node.babel_type() == "ConditionalExpression" {
                (
                    node.field(self.state.source, Field::Consequent),
                    node.field(self.state.source, Field::Alternate),
                )
            } else {
                (
                    node.field(self.state.source, Field::Left),
                    node.field(self.state.source, Field::Right),
                )
            };
            let candidates = [left, right]
                .into_iter()
                .flatten()
                .map(|branch| self.provenance_for_expression(branch, point.nested()))
                .collect::<Vec<_>>();
            let origins = unique_semantic_origins(
                &candidates
                    .iter()
                    .flat_map(provenance_origins)
                    .collect::<Vec<_>>(),
            );
            let all_modules = candidates
                .iter()
                .all(|candidate| matches!(candidate, BindingProvenance::Module { .. }));
            if all_modules && origins.len() == 1 {
                return semantic_origins_provenance(&origins);
            }
            if !origins.is_empty() {
                return semantic_ambiguous_provenance(
                    &origins,
                    if all_modules {
                        "Multiple module origins."
                    } else {
                        "Conditional provenance includes a non-module alternative."
                    },
                );
            }
            return semantic_unresolved_provenance(
                "unknown",
                "Conditional provenance is unresolved.",
            );
        }
        if is_locally_created_value(self.state.source, node) {
            return semantic_local_provenance();
        }
        semantic_unresolved_provenance(
            "unknown",
            format!("Unsupported {} provenance.", node.babel_type()),
        )
    }

    pub(super) fn provenance_for_binding_at_read(
        &mut self,
        binding: &BindingState<'a>,
        read: Node<'a>,
        point: EvaluationPoint<'a>,
    ) -> BindingProvenance {
        if opaque_effects::opaque_binding_read_may_have_changed(
            self.opaque.as_ref(),
            self.state,
            binding,
            read,
        ) {
            return semantic_ambiguous_provenance(
                &provenance_origins(&self.provenance_for_binding(binding, point)),
                "Direct eval may have changed this runtime value.",
            );
        }
        let snapshot = self.state.semantic_binding_at_read(binding, read);
        if !snapshot.selection_changed {
            return self.provenance_for_binding(binding, point);
        }
        if self.bindings.contains_key(&binding.binding_id) {
            return semantic_unresolved_provenance(
                "cycle",
                format!("Alias cycle at {}.", binding.name),
            );
        }
        self.bindings
            .insert(binding.binding_id.clone(), self.bindings.len());
        let result = self.provenance_for_binding_value(&snapshot.binding, point);
        self.bindings.remove(&binding.binding_id);
        result
    }
}

fn projection_key_string(key: &ProjectionKey) -> JsString {
    match key {
        ProjectionKey::Name(name) => name.clone(),
        ProjectionKey::Index(index) => index.to_string().into(),
        ProjectionKey::Dynamic => "".into(),
    }
}

fn provenance_origins(provenance: &BindingProvenance) -> Vec<ModuleOrigin> {
    match provenance {
        BindingProvenance::Module { origins } | BindingProvenance::Ambiguous { origins, .. } => {
            origins.clone()
        }
        _ => Vec::new(),
    }
}

fn append_origin_paths(base: BindingProvenance, path: &[JsString]) -> BindingProvenance {
    match base {
        BindingProvenance::Module { origins } => semantic_origins_provenance(
            &origins
                .into_iter()
                .map(|mut origin| {
                    origin.imported_path.extend(path.iter().cloned());
                    origin
                })
                .collect::<Vec<_>>(),
        ),
        other => other,
    }
}

fn is_locally_created_value(source: &str, node: Node<'_>) -> bool {
    read_exact_literal(source, node).is_some()
        || matches!(
            node.babel_type(),
            "ObjectExpression"
                | "ArrayExpression"
                | "FunctionExpression"
                | "FunctionDeclaration"
                | "ArrowFunctionExpression"
                | "ClassExpression"
                | "ClassDeclaration"
                | "TemplateLiteral"
                | "UnaryExpression"
                | "BinaryExpression"
                | "UpdateExpression"
        )
}
