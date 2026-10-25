//! Native `.node` addon binding shape helpers.

use std::collections::BTreeSet;

use crate::javascript::ast::{AstContext, Field, Node};
use crate::javascript::semantic::ast_values::{is_call, static_property_key};

use super::electron_values::member_path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAccess {
    pub members: Vec<String>,
    pub namespace_access: bool,
    pub dynamic_member_access: bool,
}

pub fn native_specifier(specifier: &str, require: bool) -> bool {
    let path = if require {
        specifier
    } else {
        specifier.split(['?', '#']).next().unwrap_or("")
    };
    path.to_ascii_lowercase().ends_with(".node")
}

pub fn binding_access(context: &AstContext<'_>, pattern: Node<'_>) -> NativeAccess {
    if pattern.babel_type() != "ObjectPattern" {
        return NativeAccess {
            members: Vec::new(),
            namespace_access: true,
            dynamic_member_access: false,
        };
    }
    let mut members = BTreeSet::new();
    let mut namespace_access = false;
    let mut dynamic_member_access = false;
    for property in pattern
        .field_list(context.source(), Field::Properties)
        .into_iter()
        .flatten()
    {
        if property.babel_type() == "RestElement" {
            namespace_access = true;
            continue;
        }
        let Some(key) = property.field(context.source(), Field::Key) else {
            dynamic_member_access = true;
            continue;
        };
        match static_property_key(context.source(), key, property.computed()) {
            Some(name) => {
                if let Ok(name) = name.try_to_string() {
                    members.insert(name);
                } else {
                    dynamic_member_access = true;
                }
            }
            None => dynamic_member_access = true,
        }
    }
    NativeAccess {
        members: members.into_iter().collect(),
        namespace_access,
        dynamic_member_access,
    }
}

pub fn required_addon<'a>(
    context: &AstContext<'a>,
    node: Node<'a>,
) -> Option<(String, NativeAccess)> {
    let mut current = node;
    let mut member = None;
    while current.babel_type() == "MemberExpression"
        || current.babel_type() == "OptionalMemberExpression"
    {
        let property = current.field(context.source(), Field::Property)?;
        member = static_property_key(context.source(), property, current.computed());
        current = current.field(context.source(), Field::Object)?;
    }
    if !is_call(&current) {
        return None;
    }
    let callee = current.field(context.source(), Field::Callee)?;
    let path = member_path(context, callee)?;
    let name = path.join(".");
    if name != "require" && !name.ends_with(".require") && !name.contains("__webpack_require__") {
        return None;
    }
    let argument = current
        .field_list(context.source(), Field::Arguments)
        .into_iter()
        .next()
        .flatten()?;
    let specifier = crate::javascript::static_analysis::helpers::string_value(
        context.source(),
        Some(argument),
    )?;
    if !native_specifier(specifier, true) {
        return None;
    }
    let access = match member {
        Some(member) => NativeAccess {
            members: vec![member.try_to_string().ok()?],
            namespace_access: false,
            dynamic_member_access: false,
        },
        None => NativeAccess {
            members: Vec::new(),
            namespace_access: true,
            dynamic_member_access: false,
        },
    };
    Some((specifier.to_owned(), access))
}

/// Whether an assignment writes a property below a CommonJS exports object.
pub fn is_commonjs_export_assignment(context: &AstContext<'_>, left: Node<'_>) -> bool {
    let Some(path) = member_path(context, left) else {
        return false;
    };
    (path.len() >= 2 && path[0] == "exports")
        || (path.len() >= 3 && path[0] == "module" && path[1] == "exports")
}

#[cfg(test)]
mod tests {
    use super::native_specifier;

    #[test]
    fn recognizes_node_addons_and_preserves_require_query_rules() {
        assert!(native_specifier("./binding.node", true));
        assert!(native_specifier("./binding.node?platform=darwin", false));
        assert!(!native_specifier("./binding.node?platform=darwin", true));
        assert!(!native_specifier("./binding.js", false));
    }
}
