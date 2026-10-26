//! Bounded symbolic binding resolution for demand-driven JavaScript reads.
//!
//! This resolver owns the richer values in [`super::symbolic_values`].  It is
//! deliberately separate from the ordinary semantic-value evaluator: a
//! function value retains its lexical environment, and an object value keeps
//! its properties lazy until a member is actually demanded.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::javascript::ast::{Field, Node, NodeKey};

use super::ast_values::{static_property_key, unwrapped};
use super::control_flow::{LogicalOperator, symbolic_logical_right, symbolic_truth};
use super::state::{DefinitionKind, SemanticState};
use super::symbolic_values::{
    Activation, LiteralValue, SymbolicEnvironment, SymbolicFunction, SymbolicKind, SymbolicValue,
    symbolic_array, symbolic_external, symbolic_function, symbolic_iterator, symbolic_literal,
    symbolic_object, symbolic_promise, symbolic_property, symbolic_union, symbolic_unknown,
    symbolic_variants,
};
use super::value_types::JsString;

const MAX_DEPTH: usize = 128;
const MAX_EVALUATIONS: usize = 1_000_000;

/// A bounded resolver for one semantic query.
pub struct SymbolicBindings<'state, 'a> {
    pub state: &'state SemanticState<'a>,
    pub unresolved: bool,
    pub truncated: bool,
    depth: usize,
    active: HashSet<NodeKey>,
    active_nodes: HashSet<NodeKey>,
    active_properties: HashSet<(usize, Vec<u16>)>,
    environments: HashMap<usize, CachedEnvironment<'a>>,
    member_written_bindings: HashSet<usize>,
    dynamically_written_bindings: HashSet<usize>,
    remaining_evaluations: usize,
}

impl<'state, 'a> SymbolicBindings<'state, 'a> {
    pub fn new(state: &'state SemanticState<'a>) -> Self {
        let (member_written_bindings, dynamically_written_bindings) =
            index_member_written_bindings(state);
        Self {
            state,
            unresolved: false,
            truncated: false,
            depth: 0,
            active: HashSet::new(),
            active_nodes: HashSet::new(),
            active_properties: HashSet::new(),
            environments: HashMap::new(),
            member_written_bindings,
            dynamically_written_bindings,
            remaining_evaluations: MAX_EVALUATIONS,
        }
    }

    pub fn evaluate(
        &mut self,
        node: Node<'a>,
        environment: &Rc<SymbolicEnvironment<'a>>,
    ) -> SymbolicValue<'a> {
        self.evaluate_optional(node, Some(environment.clone()))
    }

    fn evaluate_optional(
        &mut self,
        node: Node<'a>,
        environment: Option<Rc<SymbolicEnvironment<'a>>>,
    ) -> SymbolicValue<'a> {
        if self.depth >= MAX_DEPTH {
            self.truncated = true;
            return symbolic_unknown("Symbolic resolution depth exceeded.");
        }
        if self.remaining_evaluations == 0 {
            self.truncated = true;
            return symbolic_unknown("Symbolic evaluation budget exceeded.");
        }
        self.remaining_evaluations -= 1;

        let node = unwrapped(self.state.source, node);
        let environment = environment.unwrap_or_else(SymbolicEnvironment::empty);
        let environment_id = Rc::as_ptr(&environment) as usize;
        if let Some(value) = self
            .environments
            .get(&environment_id)
            .and_then(|cached| cached.values.get(&node.key()))
        {
            return value.clone();
        }
        if !self.active_nodes.insert(node.key()) {
            return symbolic_unknown("Cyclic symbolic expression.");
        }
        self.depth += 1;
        let result = self.evaluate_node(node, Some(environment.clone()));
        self.depth -= 1;
        self.active_nodes.remove(&node.key());
        self.environments
            .entry(environment_id)
            .or_insert_with(|| CachedEnvironment {
                _environment: environment,
                values: HashMap::new(),
            })
            .values
            .insert(node.key(), result.clone());
        result
    }

    /// Evaluate call arguments lazily, preserving function and object values.
    pub fn arguments(
        &mut self,
        call: Node<'a>,
        environment: &Rc<SymbolicEnvironment<'a>>,
    ) -> Vec<SymbolicValue<'a>> {
        let mut values = Vec::new();
        for argument in call
            .field_list(self.state.source, Field::Arguments)
            .into_iter()
            .flatten()
        {
            if argument.babel_type() == "SpreadElement" {
                let Some(argument) = argument.field(self.state.source, Field::Argument) else {
                    continue;
                };
                let value = self.evaluate(argument, environment);
                if let SymbolicKind::Array { values: items } = &value.kind {
                    values.extend(items.iter().cloned());
                } else {
                    values.push(symbolic_unknown("Dynamic spread arguments."));
                }
            } else {
                values.push(self.evaluate(argument, environment));
            }
        }
        values
    }

    fn evaluate_node(
        &mut self,
        node: Node<'a>,
        environment: Option<Rc<SymbolicEnvironment<'a>>>,
    ) -> SymbolicValue<'a> {
        match node.babel_type() {
            "StringLiteral" => node
                .string_value_units()
                .map(|units| {
                    symbolic_literal(LiteralValue::String(
                        super::value_types::JsString::from_utf16(units),
                    ))
                })
                .unwrap_or_else(|| self.unknown("Invalid string literal.")),
            "NumericLiteral" => node
                .numeric_value()
                .map(|value| symbolic_literal(LiteralValue::Number(value)))
                .unwrap_or_else(|| self.unknown("Invalid numeric literal.")),
            "BooleanLiteral" => node
                .boolean_value()
                .map(|value| symbolic_literal(LiteralValue::Boolean(value)))
                .unwrap_or_else(|| self.unknown("Invalid boolean literal.")),
            "NullLiteral" => symbolic_literal(LiteralValue::Null),
            "Identifier" => self.evaluate_identifier(node, environment),
            "ObjectExpression" => self.evaluate_object(node, environment),
            "ArrayExpression" => symbolic_unknown("Source array expressions are unsupported."),
            "FunctionDeclaration"
            | "FunctionExpression"
            | "ArrowFunctionExpression"
            | "ObjectMethod"
            | "ClassMethod"
            | "ClassPrivateMethod" => self.function_value(node, environment),
            "MemberExpression" | "OptionalMemberExpression" => {
                self.evaluate_member(node, environment)
            }
            "CallExpression" | "OptionalCallExpression" => self.evaluate_call(node, environment),
            "TSAsExpression"
            | "TSTypeAssertion"
            | "TSNonNullExpression"
            | "TSSatisfiesExpression"
            | "TSInstantiationExpression" => node
                .field(self.state.source, Field::Expression)
                .map(|expression| self.evaluate_optional(expression, environment))
                .unwrap_or_else(|| self.unknown("Missing wrapped expression.")),
            "SequenceExpression" => node
                .field_list(self.state.source, Field::Expressions)
                .into_iter()
                .flatten()
                .last()
                .map(|last| self.evaluate_optional(last, environment))
                .unwrap_or_else(|| symbolic_literal(LiteralValue::Undefined)),
            "AssignmentExpression" if node.operator() == Some("=") => node
                .field(self.state.source, Field::Right)
                .map(|right| self.evaluate_optional(right, environment))
                .unwrap_or_else(|| symbolic_unknown("Missing assignment value.")),
            "ConditionalExpression" => self.conditional(node, environment),
            "LogicalExpression" | "AssignmentExpression" => self.logical(node, environment),
            "UnaryExpression" => self.unary(node, environment),
            "AwaitExpression" => node
                .field(self.state.source, Field::Argument)
                .map(|argument| self.evaluate_optional(argument, environment))
                .map(Self::awaited)
                .unwrap_or_else(|| symbolic_literal(LiteralValue::Undefined)),
            _ => symbolic_unknown("Unsupported symbolic expression."),
        }
    }

    fn evaluate_identifier(
        &mut self,
        node: Node<'a>,
        environment: Option<Rc<SymbolicEnvironment<'a>>>,
    ) -> SymbolicValue<'a> {
        let Some(name) = node.identifier_name() else {
            return self.unknown("Identifier has no name.");
        };
        let Some(binding) = self.state.resolve_binding(&node, name) else {
            if !self.state.resolution_blocked(&node, name) {
                if name == "undefined" {
                    return symbolic_literal(LiteralValue::Undefined);
                }
                if matches!(name, "require" | "navigator" | "String" | "Boolean") {
                    return symbolic_external([name]);
                }
            }
            return symbolic_unknown("Binding is not statically owned.");
        };
        let reassigned = self
            .state
            .binding(binding)
            .definitions
            .iter()
            .any(|definition| definition.kind == DefinitionKind::Assignment);
        if reassigned {
            return symbolic_unknown("Binding is reassigned before the symbolic read.");
        }
        if self.dynamically_written_bindings.contains(&binding) {
            return symbolic_unknown("Binding has overwritten object members.");
        }
        if let Some(environment) = environment.as_ref() {
            if let Some(value) = environment
                .values
                .get(&self.state.binding(binding).binding_id)
                .or_else(|| {
                    environment
                        .parent
                        .as_ref()
                        .and_then(|parent| parent.lookup(&self.state.binding(binding).binding_id))
                })
            {
                return value;
            }
        }
        if self.member_written_bindings.contains(&binding) {
            return symbolic_unknown("Binding has overwritten object members.");
        }
        let binding_state = self.state.binding(binding);
        let [initializer] = binding_state.initializers.as_slice() else {
            return symbolic_unknown("Binding has no unique initializer.");
        };
        let initializer = initializer.clone();
        let boundary = environment
            .as_ref()
            .and_then(|env| self.read_boundary(&self.state.binding(binding).scope_id, env, node));
        let all_functions = self
            .state
            .binding(binding)
            .definitions
            .iter()
            .all(|definition| definition.kind == DefinitionKind::Function);
        let unavailable = !all_functions
            && initializer.entry_body.is_none()
            && boundary.is_none_or(|position| initializer.node.span().end > position);
        if unavailable {
            self.unresolved = true;
            return self.unknown("Initializer is outside the captured read boundary.");
        }
        if self
            .state
            .conditionally_skipped
            .contains(&initializer.node.key())
        {
            return symbolic_unknown("Conditional initializer.");
        }
        let mut value = self.evaluate_optional(initializer.node, environment);
        for projection in initializer.projection {
            let key = match projection {
                super::state::ProjectionKey::Name(name) => name,
                super::state::ProjectionKey::Index(index) => JsString::from(index.to_string()),
                super::state::ProjectionKey::Dynamic => {
                    return symbolic_unknown("Dynamic destructuring.");
                }
            };
            value = self.property(&value, &key);
        }
        value
    }

    fn property(&mut self, value: &SymbolicValue<'a>, key: &JsString) -> SymbolicValue<'a> {
        let identity = (Rc::as_ptr(value) as usize, key.units().to_vec());
        if !self.active_properties.insert(identity.clone()) {
            return symbolic_unknown("Cyclic symbolic property.");
        }
        if self.depth >= MAX_DEPTH || self.remaining_evaluations == 0 {
            self.active_properties.remove(&identity);
            self.truncated = true;
            return symbolic_unknown("Symbolic property resource limit.");
        }
        self.depth += 1;
        self.remaining_evaluations -= 1;

        let result = self.property_value(value, key);

        self.depth -= 1;
        self.active_properties.remove(&identity);
        result
    }

    fn property_value(&mut self, value: &SymbolicValue<'a>, key: &JsString) -> SymbolicValue<'a> {
        match &value.kind {
            SymbolicKind::Object { node, environment } => {
                self.object_property(*node, environment, key)
            }
            SymbolicKind::Union { values } => {
                let values = values.clone();
                symbolic_union(values.iter().map(|value| self.property(value, key)))
            }
            SymbolicKind::External { path } => {
                let Some(key) = key.as_str() else {
                    return symbolic_unknown("External member has a non-UTF-8 key.");
                };
                let mut path = path.clone();
                path.push(key.to_owned());
                symbolic_external(path)
            }
            SymbolicKind::Array { values } => {
                super::property_paths::semantic_array_index_units(key)
                    .and_then(|index| values.get(index))
                    .cloned()
                    .unwrap_or_else(|| symbolic_unknown("Missing argument."))
            }
            SymbolicKind::Promise { .. } | SymbolicKind::Iterator => {
                self.unresolved = true;
                symbolic_unknown("Promise or iterator members are not modeled.")
            }
            _ => key
                .as_str()
                .and_then(|key| symbolic_property(value, key))
                .unwrap_or_else(|| symbolic_unknown("Projected property is absent.")),
        }
    }

    fn object_property(
        &mut self,
        object: Node<'a>,
        environment: &Rc<SymbolicEnvironment<'a>>,
        key: &JsString,
    ) -> SymbolicValue<'a> {
        for property in object
            .field_list(self.state.source, Field::Properties)
            .into_iter()
            .flatten()
            .rev()
        {
            if property.babel_type() == "SpreadElement" {
                let Some(argument) = property.field(self.state.source, Field::Argument) else {
                    return symbolic_unknown("Missing object spread.");
                };
                let spread = self.evaluate(argument, environment);
                let found = self.property(&spread, key);
                if !matches!(found.kind, SymbolicKind::Unknown { .. }) {
                    return found;
                }
                // An unresolved spread can overwrite any earlier property.
                if !self.definitely_absent(&spread, key, &mut HashSet::new()) {
                    return found;
                }
                continue;
            }
            let Some(property_key) = property.field(self.state.source, Field::Key) else {
                continue;
            };
            let Some(name) =
                static_property_key(self.state.source, property_key, property.computed())
            else {
                return symbolic_unknown("Dynamic property overwrite.");
            };
            if &name != key {
                continue;
            }
            if property.babel_type() == "ObjectMethod" {
                if matches!(property.declaration_kind(), Some("get" | "set")) {
                    return symbolic_unknown("Accessor property.");
                }
                return self.function_value(property, Some(environment.clone()));
            }
            return property
                .field(self.state.source, Field::Value)
                .map(|value| self.evaluate(value, environment))
                .unwrap_or_else(|| symbolic_unknown("Missing object property value."));
        }
        symbolic_unknown("Projected property is absent.")
    }

    fn definitely_absent(
        &mut self,
        value: &SymbolicValue<'a>,
        key: &JsString,
        active: &mut HashSet<usize>,
    ) -> bool {
        let identity = Rc::as_ptr(value) as usize;
        if active.len() >= MAX_DEPTH || !active.insert(identity) {
            return false;
        }
        match &value.kind {
            SymbolicKind::Record { values } => {
                key.as_str().is_some_and(|key| values.get(key).is_none())
            }
            SymbolicKind::Object { node, environment } => {
                for property in node
                    .field_list(self.state.source, Field::Properties)
                    .into_iter()
                    .flatten()
                {
                    if property.babel_type() == "SpreadElement" {
                        let Some(argument) = property.field(self.state.source, Field::Argument)
                        else {
                            return false;
                        };
                        let spread = self.evaluate(argument, environment);
                        if !self.definitely_absent(&spread, key, &mut active.clone()) {
                            return false;
                        }
                    } else {
                        let name = property
                            .field(self.state.source, Field::Key)
                            .and_then(|node| {
                                static_property_key(self.state.source, node, property.computed())
                            });
                        if name.as_ref().is_none_or(|name| name == key) {
                            return false;
                        }
                    }
                }
                true
            }
            _ => false,
        }
    }

    fn evaluate_object(
        &mut self,
        node: Node<'a>,
        environment: Option<Rc<SymbolicEnvironment<'a>>>,
    ) -> SymbolicValue<'a> {
        let environment = environment.unwrap_or_else(SymbolicEnvironment::empty);
        symbolic_object(node, environment)
    }

    fn evaluate_member(
        &mut self,
        node: Node<'a>,
        environment: Option<Rc<SymbolicEnvironment<'a>>>,
    ) -> SymbolicValue<'a> {
        let Some(property) = node.field(self.state.source, Field::Property) else {
            return symbolic_unknown("Member has no property.");
        };
        let Some(key) = static_property_key(self.state.source, property, node.computed()) else {
            return symbolic_unknown("Computed member key is unresolved.");
        };
        let Some(object) = node.field(self.state.source, Field::Object) else {
            return symbolic_unknown("Member has no object.");
        };
        let value = self.evaluate_optional(object, environment);
        self.property(&value, &key)
    }

    fn evaluate_call(
        &mut self,
        node: Node<'a>,
        environment: Option<Rc<SymbolicEnvironment<'a>>>,
    ) -> SymbolicValue<'a> {
        let environment = environment.unwrap_or_else(SymbolicEnvironment::empty);
        let Some(callee) = node.field(self.state.source, Field::Callee) else {
            return symbolic_unknown("Call has no callee.");
        };
        let value = self.evaluate(callee, &environment);
        let arguments = self.arguments(node, &environment);
        let mut results = Vec::new();
        for variant in symbolic_variants(&value) {
            let result = match &variant.kind {
                SymbolicKind::External { path } if path.as_slice() == ["require"] => {
                    match arguments.first().map(|value| &value.kind) {
                        Some(SymbolicKind::Literal {
                            value: LiteralValue::String(specifier),
                        }) => specifier
                            .as_str()
                            .map(|specifier| symbolic_external([specifier]))
                            .unwrap_or_else(|| symbolic_unknown("Module identity is not UTF-8.")),
                        _ => symbolic_unknown("Dynamic require."),
                    }
                }
                SymbolicKind::Function(function) => {
                    self.call_function(function, node, arguments.clone(), &environment)
                }
                _ => symbolic_unknown("Unresolved or recursive call."),
            };
            results.push(result);
        }
        symbolic_union(results)
    }

    fn conditional(
        &mut self,
        node: Node<'a>,
        environment: Option<Rc<SymbolicEnvironment<'a>>>,
    ) -> SymbolicValue<'a> {
        let Some(test) = node.field(self.state.source, Field::Test) else {
            return symbolic_unknown("Missing condition.");
        };
        let truth = symbolic_truth(&self.evaluate_optional(test, environment.clone()));
        let fields: &[Field] = match truth {
            Some(true) => &[Field::Consequent],
            Some(false) => &[Field::Alternate],
            None => &[Field::Consequent, Field::Alternate],
        };
        symbolic_union(fields.iter().map(|field| {
            node.field(self.state.source, *field)
                .map(|branch| self.evaluate_optional(branch, environment.clone()))
                .unwrap_or_else(|| symbolic_unknown("Missing conditional branch."))
        }))
    }

    fn logical(
        &mut self,
        node: Node<'a>,
        environment: Option<Rc<SymbolicEnvironment<'a>>>,
    ) -> SymbolicValue<'a> {
        let operator = match node.operator() {
            Some("&&" | "&&=") => LogicalOperator::And,
            Some("||" | "||=") => LogicalOperator::Or,
            Some("??" | "??=") => LogicalOperator::Nullish,
            _ => return symbolic_unknown("Unsupported assignment operator."),
        };
        let Some(left) = node.field(self.state.source, Field::Left) else {
            return symbolic_unknown("Missing logical operand.");
        };
        let value = self.evaluate_optional(left, environment.clone());
        let reach_right = symbolic_logical_right(operator, &value);
        if reach_right == Some(false) {
            return value;
        }
        let right = node
            .field(self.state.source, Field::Right)
            .map(|right| self.evaluate_optional(right, environment))
            .unwrap_or_else(|| symbolic_unknown("Missing logical operand."));
        if reach_right == Some(true) {
            right
        } else {
            symbolic_union([value, right])
        }
    }

    fn unary(
        &mut self,
        node: Node<'a>,
        environment: Option<Rc<SymbolicEnvironment<'a>>>,
    ) -> SymbolicValue<'a> {
        let value = node
            .field(self.state.source, Field::Argument)
            .map(|argument| self.evaluate_optional(argument, environment))
            .unwrap_or_else(|| symbolic_unknown("Missing unary operand."));
        match node.operator() {
            Some("void") => symbolic_literal(LiteralValue::Undefined),
            Some("!") => symbolic_truth(&value)
                .map(|truth| symbolic_literal(LiteralValue::Boolean(!truth)))
                .unwrap_or_else(|| symbolic_unknown("Unknown unary truth.")),
            _ => symbolic_unknown("Unsupported unary operator."),
        }
    }

    fn awaited(value: SymbolicValue<'a>) -> SymbolicValue<'a> {
        symbolic_union(
            symbolic_variants(&value)
                .into_iter()
                .map(|variant| match &variant.kind {
                    SymbolicKind::Promise { value, .. } => Self::awaited(value.clone()),
                    _ => variant,
                }),
        )
    }

    fn call_function(
        &mut self,
        function: &SymbolicFunction<'a>,
        invocation: Node<'a>,
        arguments: Vec<SymbolicValue<'a>>,
        caller: &Rc<SymbolicEnvironment<'a>>,
    ) -> SymbolicValue<'a> {
        let (asynchronous, generator) =
            crate::javascript::static_analysis::babel::function_flags(&function.node)
                .unwrap_or_default();
        if generator {
            return symbolic_iterator();
        }
        if !self.active.insert(function.node.key()) {
            return symbolic_unknown("Recursive symbolic function call.");
        }

        let activation = self.bind(function, arguments, invocation, Some(caller.clone()));
        let result = self.find_return(function.node, activation.clone());
        self.active.remove(&function.node.key());
        let result = Self::complete_returned_value(
            result,
            &activation,
            function
                .node
                .field(self.state.source, Field::Body)
                .unwrap_or(function.node),
        );
        if asynchronous {
            symbolic_promise(Self::awaited(result), None)
        } else {
            result
        }
    }

    pub fn bind(
        &self,
        function: &SymbolicFunction<'a>,
        arguments: Vec<SymbolicValue<'a>>,
        invocation: Node<'a>,
        caller: Option<Rc<SymbolicEnvironment<'a>>>,
    ) -> Rc<SymbolicEnvironment<'a>> {
        let mut values = super::symbolic_values::SymbolicMap::new();
        for (index, parameter) in
            super::ast_values::runtime_function_parameters(self.state.source, &function.node)
                .into_iter()
                .enumerate()
        {
            let rest = parameter.babel_type() == "RestElement";
            let target = if rest {
                parameter.field(self.state.source, Field::Argument)
            } else {
                Some(parameter)
            };
            let Some(target) = target else { continue };
            let Some(name) = target.identifier_name() else {
                continue;
            };
            let Some(binding) = self.state.resolve_binding(&target, name) else {
                continue;
            };
            let value = if rest {
                symbolic_array(arguments.get(index..).unwrap_or_default().to_vec())
            } else {
                arguments
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| symbolic_unknown("Runtime parameter."))
            };
            values.insert(self.state.binding(binding).binding_id.clone(), value);
        }
        Rc::new(SymbolicEnvironment {
            values,
            parent: Some(function.environment.clone()),
            activation: Rc::new(Activation),
            caller,
            point: Some(invocation),
            scope_id: self
                .state
                .scope_for_node(&function.node)
                .map(|index| self.state.scope(index).scope_id.clone()),
            scope_node: Some(function.node),
            completed_at: None,
            common_through: None,
        })
    }

    fn read_boundary(
        &self,
        binding_scope: &str,
        environment: &Rc<SymbolicEnvironment<'a>>,
        read: Node<'a>,
    ) -> Option<u32> {
        let mut current = Some(environment.clone());
        let mut child = None;
        while let Some(candidate) = current {
            if candidate
                .scope_id
                .as_deref()
                .is_some_and(|scope| self.state.scope_is_within(binding_scope, scope))
            {
                if let Some(completed) = candidate.completed_at {
                    return Some(completed.span().end);
                }
                let point = child
                    .and_then(|env: Rc<SymbolicEnvironment<'a>>| env.point)
                    .unwrap_or(read);
                if let Some(scope_node) = candidate.scope_node
                    && !self.node_within(point, scope_node)
                {
                    return None;
                }
                return Some(point.span().start);
            }
            child = Some(candidate.clone());
            current = candidate.parent.clone();
        }
        let mut outermost = environment.clone();
        while let Some(parent) = outermost.parent.clone() {
            outermost = parent;
        }
        Some(
            outermost
                .point
                .or(environment.point)
                .unwrap_or(read)
                .span()
                .start,
        )
    }

    fn node_within(&self, node: Node<'a>, ancestor: Node<'a>) -> bool {
        let mut current = Some(node);
        while let Some(candidate) = current {
            if candidate.key() == ancestor.key() {
                return true;
            }
            current = self.state.parent_of(&candidate);
        }
        false
    }

    fn find_return(
        &mut self,
        function: Node<'a>,
        environment: Rc<SymbolicEnvironment<'a>>,
    ) -> SymbolicValue<'a> {
        let Some(body) = function.field(self.state.source, Field::Body) else {
            return symbolic_literal(LiteralValue::Undefined);
        };
        if body.babel_type() != "BlockStatement" {
            return self.evaluate(body, &environment);
        }
        let statements = body
            .field_list(self.state.source, Field::Body)
            .into_iter()
            .flatten()
            .collect();
        let mut flow = self.return_flow(statements, &environment, 0);
        if flow.falls_through {
            flow.values.push(symbolic_literal(LiteralValue::Undefined));
        }
        symbolic_union(flow.values)
    }

    fn return_flow(
        &mut self,
        statements: Vec<Node<'a>>,
        environment: &Rc<SymbolicEnvironment<'a>>,
        depth: usize,
    ) -> ReturnFlow<'a> {
        let mut values = Vec::new();
        for statement in statements {
            if depth >= MAX_DEPTH || self.remaining_evaluations == 0 {
                self.truncated = true;
                values.push(symbolic_unknown("Symbolic return resource limit."));
                return ReturnFlow {
                    values,
                    falls_through: false,
                };
            }
            self.remaining_evaluations -= 1;
            match statement.babel_type() {
                "ThrowStatement" => {
                    values.push(symbolic_unknown("Wrapper exits by throwing."));
                    return ReturnFlow {
                        values,
                        falls_through: false,
                    };
                }
                "ReturnStatement" => {
                    let value = statement
                        .field(self.state.source, Field::Argument)
                        .map(|argument| self.evaluate(argument, environment))
                        .unwrap_or_else(|| symbolic_literal(LiteralValue::Undefined));
                    values.push(Self::returned_at(value, statement));
                    return ReturnFlow {
                        values,
                        falls_through: false,
                    };
                }
                "BlockStatement" => {
                    let statements = statement
                        .field_list(self.state.source, Field::Body)
                        .into_iter()
                        .flatten()
                        .collect();
                    let flow = self.return_flow(statements, environment, depth + 1);
                    values.extend(flow.values);
                    if !flow.falls_through {
                        return ReturnFlow {
                            values,
                            falls_through: false,
                        };
                    }
                }
                "IfStatement" => {
                    let truth = statement
                        .field(self.state.source, Field::Test)
                        .and_then(|test| symbolic_truth(&self.evaluate(test, environment)));
                    let fields: &[Field] = match truth {
                        Some(true) => &[Field::Consequent],
                        Some(false) => &[Field::Alternate],
                        None => &[Field::Consequent, Field::Alternate],
                    };
                    let mut falls_through = false;
                    for field in fields {
                        let branch = statement
                            .field(self.state.source, *field)
                            .into_iter()
                            .collect();
                        let flow = self.return_flow(branch, environment, depth + 1);
                        values.extend(flow.values);
                        falls_through |= flow.falls_through;
                    }
                    if !falls_through {
                        return ReturnFlow {
                            values,
                            falls_through: false,
                        };
                    }
                }
                "ForStatement" | "ForInStatement" | "ForOfStatement" | "WhileStatement"
                | "DoWhileStatement" | "SwitchStatement" | "TryStatement" | "LabeledStatement"
                | "WithStatement" => {
                    if self.contains_owned_return(statement) {
                        values.push(symbolic_unknown("Unsupported return control flow."));
                    }
                }
                _ => {}
            }
        }
        ReturnFlow {
            values,
            falls_through: true,
        }
    }

    fn contains_owned_return(&self, root: Node<'a>) -> bool {
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            if super::ast_values::is_function(&node) || super::ast_values::is_class(&node) {
                continue;
            }
            if node.babel_type() == "ReturnStatement" {
                return true;
            }
            pending.extend(self.state.context.children(&node));
        }
        false
    }

    fn returned_at(value: SymbolicValue<'a>, point: Node<'a>) -> SymbolicValue<'a> {
        symbolic_union(symbolic_variants(&value).into_iter().map(|variant| {
            let mut returned = (*variant).clone();
            match &mut returned.kind {
                SymbolicKind::Function(function) => function.return_point = Some(point),
                SymbolicKind::Promise { return_point, .. } => *return_point = Some(point),
                _ => return variant,
            }
            Rc::new(returned)
        }))
    }

    fn complete_returned_value(
        value: SymbolicValue<'a>,
        activation: &Rc<SymbolicEnvironment<'a>>,
        fallback: Node<'a>,
    ) -> SymbolicValue<'a> {
        symbolic_union(symbolic_variants(&value).into_iter().map(|variant| {
            let mut returned = (*variant).clone();
            match &mut returned.kind {
                SymbolicKind::Function(function) => {
                    let point = function.return_point.take().unwrap_or(fallback);
                    if let Some(environment) =
                        Self::completed_environment(&function.environment, activation, point)
                    {
                        function.environment = environment;
                    }
                }
                SymbolicKind::Promise {
                    value,
                    return_point,
                } => {
                    let point = return_point.take().unwrap_or(fallback);
                    *value = Self::complete_returned_value(value.clone(), activation, point);
                }
                _ => return variant,
            }
            Rc::new(returned)
        }))
    }

    fn completed_environment(
        environment: &Rc<SymbolicEnvironment<'a>>,
        activation: &Rc<SymbolicEnvironment<'a>>,
        point: Node<'a>,
    ) -> Option<Rc<SymbolicEnvironment<'a>>> {
        let mut completed = (**environment).clone();
        if Rc::ptr_eq(environment, activation) {
            completed.completed_at = Some(point);
        } else {
            completed.parent = Some(Self::completed_environment(
                environment.parent.as_ref()?,
                activation,
                point,
            )?);
        }
        Some(Rc::new(completed))
    }

    fn function_value(
        &self,
        node: Node<'a>,
        environment: Option<Rc<SymbolicEnvironment<'a>>>,
    ) -> SymbolicValue<'a> {
        symbolic_function(SymbolicFunction {
            node,
            environment: environment.unwrap_or_else(SymbolicEnvironment::empty),
            origins: vec![node],
            return_point: None,
        })
    }

    fn unknown(&mut self, reason: &'static str) -> SymbolicValue<'a> {
        symbolic_unknown(reason)
    }
}

struct ReturnFlow<'a> {
    values: Vec<SymbolicValue<'a>>,
    falls_through: bool,
}

struct CachedEnvironment<'a> {
    // Retain the owner so an allocator cannot reuse an environment identity.
    _environment: Rc<SymbolicEnvironment<'a>>,
    values: HashMap<NodeKey, SymbolicValue<'a>>,
}

fn index_member_written_bindings(state: &SemanticState<'_>) -> (HashSet<usize>, HashSet<usize>) {
    let mut written = HashSet::new();
    let mut dynamic = HashSet::new();
    let mut pending = vec![state.program];
    while let Some(node) = pending.pop() {
        pending.extend(state.context.children(&node));
        let Some(target) = super::ast_values::write_site_target(state.source, &node) else {
            continue;
        };
        let exact = matches!(
            unwrapped(state.source, target).babel_type(),
            "Identifier" | "MemberExpression"
        );
        for target in super::ast_values::write_targets(state.source, target) {
            let mut root = unwrapped(state.source, target);
            let mut is_dynamic = !exact;
            let mut member = false;
            while matches!(
                root.babel_type(),
                "MemberExpression" | "OptionalMemberExpression"
            ) {
                member = true;
                is_dynamic |= root
                    .field(state.source, Field::Property)
                    .and_then(|property| {
                        static_property_key(state.source, property, root.computed())
                    })
                    .is_none();
                let Some(object) = root.field(state.source, Field::Object) else {
                    break;
                };
                root = unwrapped(state.source, object);
            }
            let Some(name) = root.identifier_name() else {
                continue;
            };
            let Some(binding) = state.resolve_binding(&root, name) else {
                continue;
            };
            if is_dynamic {
                dynamic.insert(binding);
            } else if member {
                written.insert(binding);
            }
        }
    }
    (written, dynamic)
}
