//! Syntax-owned option object inspection for Electron constructors.

use std::cmp::Ordering;

use crate::javascript::ast::{AstContext, Field, Node};
use crate::javascript::contracts::static_analysis::{OptionsStatus, StaticValue, WebPreference};
use crate::javascript::semantic::ast_values::{
    ExactLiteral, StaticObjectProperty, read_exact_literal, static_object_property,
    static_property_key, unwrapped,
};
use crate::javascript::semantic::value_types::{JsString, Primitive};

use super::electron_values::electron_static_value;
use super::helpers::{StaticPathContext, static_path, static_path_resolution_context};

#[derive(Clone, Debug, PartialEq)]
pub struct ElectronOptions {
    pub status: OptionsStatus,
    pub web_preferences_status: OptionsStatus,
    pub web_preferences: Vec<WebPreference>,
    pub preload: Option<JsString>,
    pub preload_resolution_context: Option<StaticPathContext>,
    /// Number of preference entries whose key or spread could not be resolved.
    pub unknown: u64,
}

/// Inspect the constructor options while preserving effective property order.
pub fn inspect_options<'a>(context: &AstContext<'a>, node: Option<Node<'a>>) -> ElectronOptions {
    inspect_options_with_resolver(context, node, &|_| None)
}

/// Inspect options after applying the caller's proven constant-object resolver.
/// The resolver is deliberately supplied by the semantic owner so this module
/// never guesses whether an identifier is stable or mutated.
pub fn inspect_options_with_resolver<'a>(
    context: &AstContext<'a>,
    node: Option<Node<'a>>,
    resolve: &impl Fn(Node<'a>) -> Option<Node<'a>>,
) -> ElectronOptions {
    let Some(node) = node else {
        return missing_options();
    };

    let options = resolve_alias(context, unwrapped(context.source(), node), resolve);
    if options.babel_type() != "ObjectExpression" {
        return dynamic_options();
    }

    let web_preferences =
        static_object_property(context.source(), Some(options), "webPreferences", None);

    let (web_preferences_status, preferences_object) = match web_preferences {
        StaticObjectProperty::Missing => (OptionsStatus::Missing, None),
        StaticObjectProperty::Dynamic => (OptionsStatus::Dynamic, None),
        StaticObjectProperty::Explicit(property) => {
            let value: Option<Node<'a>> = property
                .field(context.source(), Field::Value)
                .map(|value| unwrapped(context.source(), value))
                .map(|value| resolve_alias(context, value, resolve));
            match value.filter(|value| value.babel_type() == "ObjectExpression") {
                Some(value) => (OptionsStatus::ObjectLiteral, Some(value)),
                None => (OptionsStatus::Dynamic, None),
            }
        }
    };

    let (web_preferences, unknown) = preferences_object
        .map(|object| collect_preferences(context, object))
        .unwrap_or_default();
    let (preload, preload_resolution_context) = preferences_object
        .map(|object| effective_preload(context, object))
        .unwrap_or((None, None));

    ElectronOptions {
        status: OptionsStatus::ObjectLiteral,
        web_preferences_status,
        web_preferences,
        preload,
        preload_resolution_context,
        unknown: unknown + u64::from(matches!(web_preferences_status, OptionsStatus::Dynamic)),
    }
}

fn effective_preload<'a>(
    context: &AstContext<'a>,
    preferences: Node<'a>,
) -> (Option<JsString>, Option<StaticPathContext>) {
    let property =
        match static_object_property(context.source(), Some(preferences), "preload", None) {
            StaticObjectProperty::Explicit(property) => property,
            StaticObjectProperty::Missing | StaticObjectProperty::Dynamic => return (None, None),
        };
    let Some(value) = property
        .field(context.source(), Field::Value)
        .map(|value| unwrapped(context.source(), value))
    else {
        return (None, None);
    };
    let Some(path) = static_preload_path(context, value) else {
        return (None, None);
    };
    (
        Some(path),
        Some(static_path_resolution_context(context, value)),
    )
}

fn static_preload_path<'a>(context: &AstContext<'a>, value: Node<'a>) -> Option<JsString> {
    if let Some(ExactLiteral::String(value)) = read_exact_literal(context.source(), value) {
        return Some(value);
    }

    static_path(context, value).map(JsString::from)
}

fn resolve_alias<'a>(
    context: &AstContext<'a>,
    mut node: Node<'a>,
    resolve: &impl Fn(Node<'a>) -> Option<Node<'a>>,
) -> Node<'a> {
    for _ in 0..8 {
        if node.babel_type() != "Identifier" {
            break;
        }
        let Some(resolved) = resolve(node) else {
            break;
        };
        let resolved = unwrapped(context.source(), resolved);
        if context.start(&resolved) == context.start(&node)
            && context.end(&resolved) == context.end(&node)
        {
            break;
        }
        node = resolved;
    }
    node
}

fn collect_preferences<'a>(
    context: &AstContext<'a>,
    object: Node<'a>,
) -> (Vec<WebPreference>, u64) {
    let mut preferences = Vec::new();
    let mut unknown = 0_u64;

    for property in object
        .field_list(context.source(), Field::Properties)
        .into_iter()
        .flatten()
    {
        if property.babel_type() == "SpreadElement" {
            unknown += 1;
            preferences.push(WebPreference {
                name: JsString::from(format!("[spread@{}]", context.start(&property))),
                value: electron_static_value(
                    context,
                    property.field(context.source(), Field::Argument),
                ),
            });
            continue;
        }

        let Some(key) = property.field(context.source(), Field::Key) else {
            unknown += 1;
            continue;
        };
        let Some(name) = static_property_key(context.source(), key, property.computed()) else {
            unknown += 1;
            preferences.push(WebPreference {
                name: JsString::from(format!("[dynamic@{}]", context.start(&property))),
                value: electron_static_value(context, Some(property)),
            });
            continue;
        };

        let value = if property.babel_type() == "ObjectMethod" {
            electron_static_value(context, Some(property))
        } else {
            electron_static_value(context, property.field(context.source(), Field::Value))
        };
        let value = if name == "preload" {
            property
                .field(context.source(), Field::Value)
                .map(|value| unwrapped(context.source(), value))
                .and_then(|value| static_preload_path(context, value))
                .map(|path| StaticValue {
                    status: "literal".to_owned(),
                    value: Primitive::String(path),
                    expression: None,
                })
                .unwrap_or(value)
        } else {
            value
        };
        if property.babel_type() == "ObjectMethod" || value.status == "dynamic" {
            unknown += 1;
        }
        preferences.push(WebPreference { name, value });
    }

    preferences.sort_by(|left, right| {
        let ordering = left.name.compare_code_points(&right.name);
        if ordering == Ordering::Equal {
            left.name.cmp(&right.name)
        } else {
            ordering
        }
    });
    (preferences, unknown)
}

fn missing_options() -> ElectronOptions {
    ElectronOptions {
        status: OptionsStatus::Missing,
        web_preferences_status: OptionsStatus::Missing,
        web_preferences: Vec::new(),
        preload: None,
        preload_resolution_context: None,
        unknown: 0,
    }
}

fn dynamic_options() -> ElectronOptions {
    ElectronOptions {
        status: OptionsStatus::Dynamic,
        web_preferences_status: OptionsStatus::Dynamic,
        web_preferences: Vec::new(),
        preload: None,
        preload_resolution_context: None,
        unknown: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::inspect_options;
    use crate::javascript::ast::{AstContext, Field};
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::value_types::JsString;
    use oxc_allocator::Allocator;

    #[test]
    fn counts_dynamic_and_method_preferences_and_uses_effective_preload() {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(
            &allocator,
            "new BrowserWindow({ webPreferences: { sandbox: flag, method() {}, preload: 'old.js', preload: 'new.js' } });",
            Some("main.js"),
        )
        .expect("parse BrowserWindow options");
        let context = AstContext::new(parsed.program);
        let statement = context.children(&context.root())[0];
        let expression = statement
            .field(context.source(), Field::Expression)
            .expect("constructor expression");
        let options = expression
            .field_list(context.source(), Field::Arguments)
            .into_iter()
            .next()
            .flatten();

        let inspected = inspect_options(&context, options);

        assert_eq!(inspected.unknown, 2);
        assert_eq!(inspected.preload.as_ref(), Some(&JsString::from("new.js")));
        assert_eq!(inspected.web_preferences.len(), 4);
    }

    #[test]
    fn preserves_unpaired_surrogate_in_preload_literal() {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(
            &allocator,
            r#"new BrowserWindow({ webPreferences: { preload: "\uD800.js" } });"#,
            Some("main.js"),
        )
        .expect("parse BrowserWindow options");
        let context = AstContext::new(parsed.program);
        let statement = context.children(&context.root())[0];
        let expression = statement
            .field(context.source(), Field::Expression)
            .expect("constructor expression");
        let options = expression
            .field_list(context.source(), Field::Arguments)
            .into_iter()
            .next()
            .flatten();

        let inspected = inspect_options(&context, options);
        let preload = inspected.preload.expect("literal preload");

        assert_eq!(
            preload.units(),
            &[0xd800, b'.' as u16, b'j' as u16, b's' as u16]
        );
    }
}
