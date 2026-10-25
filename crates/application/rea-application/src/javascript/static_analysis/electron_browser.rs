//! BrowserWindow constructor shape extraction.

use super::electron_options::{ElectronOptions, inspect_options_with_resolver};
use super::helpers::StaticPathContext;
use crate::javascript::ast::{AstContext, Node};
use crate::javascript::semantic::value_types::JsString;

#[derive(Clone, Debug, PartialEq)]
pub struct BrowserWindowShape {
    pub options: ElectronOptions,
    pub preload: Option<JsString>,
    pub preload_resolution_context: Option<StaticPathContext>,
}

/// Extract a shape while resolving only aliases proven stable by the semantic
/// owner. This keeps syntax inspection independent from mutation policy.
pub fn browser_window_shape_with_resolver<'a>(
    context: &AstContext<'a>,
    node: Node<'a>,
    options: Option<Node<'a>>,
    resolve: &impl Fn(Node<'a>) -> Option<Node<'a>>,
) -> Option<BrowserWindowShape> {
    if node.babel_type() != "NewExpression" {
        return None;
    }
    let inspected = inspect_options_with_resolver(context, options, resolve);
    let preload = inspected.preload.clone();
    let preload_resolution_context = inspected.preload_resolution_context;
    Some(BrowserWindowShape {
        options: inspected,
        preload,
        preload_resolution_context,
    })
}

#[cfg(test)]
mod tests {
    use super::browser_window_shape_with_resolver;
    use crate::javascript::ast::{AstContext, Field};
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::value_types::JsString;
    use oxc_allocator::Allocator;

    #[test]
    fn extracts_literal_browser_window_preferences() {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(
            &allocator,
            "new BrowserWindow({ webPreferences: { preload: './preload.js', sandbox: true } });",
            Some("main.js"),
        )
        .expect("parse");
        let context = AstContext::new(parsed.program);
        let statement = context.children(&context.root())[0];
        let expression = statement
            .field(context.source(), Field::Expression)
            .expect("expression");
        let options = expression
            .field_list(context.source(), Field::Arguments)
            .into_iter()
            .next()
            .flatten();
        let shape = browser_window_shape_with_resolver(&context, expression, options, &|_| None)
            .expect("BrowserWindow");
        assert_eq!(
            shape.preload.as_ref(),
            Some(&JsString::from("./preload.js"))
        );
        assert_eq!(shape.options.web_preferences.len(), 2);
    }
}
