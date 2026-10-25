//! Argument selection for Electron `contextBridge` exposure methods.

use crate::javascript::ast::{Field, Node};
use crate::javascript::contracts::static_analysis::StaticValue;

use super::electron_values::{collect_context_bridge_members, electron_static_value};
use crate::javascript::ast::AstContext;
use crate::javascript::semantic::value_types::JsString;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExposureWorld {
    Main,
    Isolated,
}

pub struct ExposureArguments<'a> {
    pub world: ExposureWorld,
    pub world_id: Option<StaticValue>,
    pub api_key: Option<Node<'a>>,
    pub api: Option<Node<'a>>,
}

pub fn exposure_arguments<'a>(
    context: &AstContext<'a>,
    method: &str,
    call: Node<'a>,
) -> Option<ExposureArguments<'a>> {
    let arguments = call.field_list(context.source(), Field::Arguments);
    let node = |index: usize| arguments.get(index).copied().flatten();
    match method {
        "exposeInMainWorld" => Some(ExposureArguments {
            world: ExposureWorld::Main,
            world_id: None,
            api_key: node(0),
            api: node(1),
        }),
        "exposeInIsolatedWorld" => Some(ExposureArguments {
            world: ExposureWorld::Isolated,
            world_id: node(0).map(|value| electron_static_value(context, Some(value))),
            api_key: node(1),
            api: node(2),
        }),
        _ => None,
    }
}

pub fn members_for_exposure(
    context: &AstContext<'_>,
    api: Option<Node<'_>>,
) -> (String, Vec<JsString>, u64) {
    let (status, members, unknown) = collect_context_bridge_members(context, api);
    let status = if unknown == 0 {
        status
    } else {
        "dynamic".to_owned()
    };
    (status, members, unknown)
}

#[cfg(test)]
mod tests {
    use super::{ExposureWorld, exposure_arguments, members_for_exposure};
    use crate::javascript::ast::{AstContext, Field};
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::value_types::JsString;
    use oxc_allocator::Allocator;

    #[test]
    fn selects_main_world_api_and_nested_members() {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(
            &allocator,
            "contextBridge.exposeInMainWorld('api', { nested: { call() {}, value: 1 } });",
            Some("preload.js"),
        )
        .expect("parse");
        let context = AstContext::new(parsed.program);
        let statement = context.children(&context.root())[0];
        let call = statement
            .field(context.source(), Field::Expression)
            .expect("call");
        let args = exposure_arguments(&context, "exposeInMainWorld", call).expect("exposure");
        assert_eq!(args.world, ExposureWorld::Main);
        let (status, members, unknown) = members_for_exposure(&context, args.api);
        assert_eq!(status, "object-literal");
        assert!(members.contains(&JsString::from("nested")));
        assert!(members.contains(&JsString::from("nested.call")));
        assert_eq!(unknown, 0);
    }
}
