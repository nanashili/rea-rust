//! Direct provider-operation proxies (catalog kind `official-proxy`).
//!
//! Compatibility owners: `src/server/registerOfficialTools.ts` and
//! `src/contracts/officialToolContracts.ts`. Each call runs inside session
//! admission; the session applies capability gating, snapshot replay,
//! mutation invalidation and profile/subject binding, and the result is
//! delivered as `createAnalysisExecutionEvidence`.
use crate::Registration;
use crate::port::AnalysisPort;
use crate::refine;
use crate::session::tools_of_kind;
use rea_analysis::ExecutionOptions;
use rea_mcp::support::arguments;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::Value;
use std::sync::Arc;

pub(crate) fn register(registry: &mut Registry, registration: &Arc<Registration>) {
    for name in tools_of_kind("official-proxy") {
        let registration = Arc::clone(registration);
        registry.handle(name, move |context, input| {
            official_tool(&registration, context, &input)
        });
    }
}

fn official_tool(
    registration: &Registration,
    context: &ToolContext<'_>,
    input: &Value,
) -> ToolOutput {
    if let Some(failure) = refine::check(context.contract, input) {
        return failure;
    }
    let name = context.name_static();
    let state = registration.bind(context.session);
    let parameters = arguments(input);
    let admitted =
        state.with_admitted_analysis(context.session, name, &context.cancellation, |port| {
            context.progress.report(name, "started");
            let reporter = context.progress.clone();
            let options = ExecutionOptions {
                cancellation: context.cancellation.clone(),
                progress: Some(Arc::new(move |phase: &str, message: &str| {
                    reporter.report(phase, message);
                })),
                selector_from_provider: false,
            };
            let result = port.execute(name, &parameters, &options);
            context.progress.report(
                name,
                if result.is_ok() {
                    "completed"
                } else {
                    "failed"
                },
            );
            match result {
                Err(error) => ToolOutput::Failure(error),
                Ok(mut execution) => {
                    if execution.subject.is_none() {
                        execution.subject = port.active_target().map(|target| target.subject());
                    }
                    execution
                        .evidence(name, Value::Object(parameters.clone()), "observed")
                        .into()
                }
            }
        });
    admitted.unwrap_or_else(ToolOutput::Failure)
}
